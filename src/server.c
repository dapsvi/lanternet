/* server.c - the single long-running server */
#include "lanternet.h"
#include "jsonlite.h"
#include "selector.h"
#include "actions.h"

#include <sys/epoll.h>
#include <sys/file.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <net/if.h>

#define TICK_MS      50
#define PROBE_SLOW   1        /* ARP probes per tick, background continuous (rare) */
#define MAXCONN      8

static int g_ep=-1, g_lfd=-1;
static int g_md=-1, g_ns=-1, g_ic=-1, g_dh=-1, g_sd=-1, g_dn=-1;

/* scanner */
static unsigned long g_sweep_first, g_sweep_last, g_sweep_cur;
static int g_sweep_init=0, g_scan_on=0;   /* g_scan_on: continuous background discovery (opt-in, default OFF) */
int g_enrich=1;                          /* 1 = send mDNS/NBNS/ICMP name probes */
static int  open_discovery(void);
static void close_discovery(void);
static unsigned long g_pass_until=0;
static unsigned long g_disc_off=0;
static int g_enrich_i=0;

/* pacing */
static double g_bucket=0;
static unsigned long g_bucket_ms=0;

/* timers */
static unsigned long g_next_merge, g_next_hb, g_next_keep, g_next_browse;
static unsigned long g_next_sweep;      /* idle gate between background sweeps */
static unsigned long g_next_enrich;     /* idle gate between name-probe steps */
static int g_browse_stage=-1;

/* lock */
static int g_lock_fd=-1;

struct conn { int fd; char buf[8192]; int n; unsigned long deadline; };
static struct conn conns[MAXCONN];

static unsigned short g_icmp_id;

/* lock file */
static int boot_id(char *out,size_t n){
    FILE *f=fopen("/proc/sys/kernel/random/boot_id","r");
    if(!f){ snprintf(out,n,"?"); return 0; }
    if(!fgets(out,n,f)) out[0]=0;
    fclose(f);
    out[strcspn(out,"\r\n")]=0;
    return out[0]!=0;
}
static long proc_starttime(pid_t pid){
    char path[64]; snprintf(path,sizeof path,"/proc/%d/stat",(int)pid);
    FILE *f=fopen(path,"r");
    if(!f) return 0;
    char line[1024];
    if(!fgets(line,sizeof line,f)){ fclose(f); return 0; }
    fclose(f);
    char *p=strrchr(line,')');
    if(!p) return 0;
    p++;
    long v=0; int field=3;          /* field 3 is state, right after ")" */
    char *tok=strtok(p," ");
    while(tok){
        if(field==22){ v=atol(tok); break; }
        field++; tok=strtok(NULL," ");
    }
    return v;
}

static void lock_write(void){
    if(g_lock_fd<0) return;
    char b[64]; boot_id(b,sizeof b);
    char line[256];
    int L=snprintf(line,sizeof line,"pid=%d boot=%s start=%ld mono=%lu\n",
                   (int)getpid(), b, proc_starttime(getpid()), now_ms());
    lseek(g_lock_fd,0,SEEK_SET);
    if(ftruncate(g_lock_fd,0)==0) { ssize_t w=write(g_lock_fd,line,(size_t)L); (void)w; }
    fsync(g_lock_fd);
}

/* returns 0 if we own the lock, 1 if another server holds it, 2 on error */
static int lock_acquire(void){
    g_lock_fd=open(LOCK_PATH,O_RDWR|O_CREAT,0600);
    if(g_lock_fd<0) return 2;
    if(flock(g_lock_fd,LOCK_EX|LOCK_NB)!=0){
        char b[512]={0};
        lseek(g_lock_fd,0,SEEK_SET);
        ssize_t r=read(g_lock_fd,b,sizeof b-1);
        (void)r;
        char *p=strstr(b,"pid=");
        int pid=p?atoi(p+4):0;
        fprintf(stderr,"lanternet: already running%s%s\n",
                pid?" (pid ":"", pid?"":"");
        if(pid) fprintf(stderr,"%d\n",pid);
        fprintf(stderr,"  stop it with: lanternet shutdown\n");
        return 1;
    }
    lock_write();
    return 0;
}
static void lock_release(void){
    if(g_lock_fd<0) return;
    unlink(LOCK_PATH);
    close(g_lock_fd);
    g_lock_fd=-1;
}

/* scanner */
static unsigned long ntohl_u(unsigned int x){ return (unsigned long)ntohl(x); }
static unsigned int htonl_u(unsigned long x){ return htonl((unsigned int)x); }

static void scanner_reset(void){
    unsigned int net = g_myip & g_mask;
    unsigned int bc  = g_myip | ~g_mask;
    g_sweep_first = ntohl_u(net) + 1;
    g_sweep_last  = ntohl_u(bc) - 1;
    if(g_sweep_last < g_sweep_first) g_sweep_last = g_sweep_first;
    g_sweep_cur = g_sweep_first;
    g_sweep_init=1;
}

static void merge_arp_file(void){
    FILE *f=fopen("/proc/net/arp","r");
    if(!f) return;
    char line[256]; int first=1;
    while(fgets(line,sizeof line,f)){
        if(first){ first=0; continue; }
        char ips[32],hws[32]; unsigned type,flags;
        if(sscanf(line,"%31s %x %x %31s",ips,&type,&flags,hws)<4) continue;
        unsigned int ip; unsigned char mac[6];
        if(inet_pton(AF_INET,ips,&ip)!=1) continue;
        if(!parse_mac(hws,mac)) continue;
        add_host(ip,mac);
    }
    fclose(f);
}

static int truthy(const char *v){ return (!strcasecmp(v,"true")||atoi(v))?1:0; }

static int g_ping_active=0, g_ping_i=0, g_ping_budget=0;

static void ping_start(int budget){
    if(g_ic<0) return;
    g_ping_i=0; g_ping_budget=budget; g_ping_active=1;
}

static void ping_tick(void){
    if(!g_ping_active) return;
    if(g_ic<0){ g_ping_active=0; return; }
    if(g_ping_i>=g_nhost){ g_ping_active=0; return; }
    int n = g_ping_budget>0 ? g_ping_budget : g_nhost;
    for(int k=0;k<n && g_ping_i<g_nhost;k++,g_ping_i++)
        icmp_echo(g_ic,g_hosts[g_ping_i].ip,g_icmp_id);
}

static void scan_tick(void){
    if(!g_scan_on) return;               /* idle server transmits NOTHING */
    if(!g_sweep_init) scanner_reset();
    unsigned long now=now_ms();
    if(now<g_next_sweep) return;
    static const unsigned char bcastmac[6]={0xff,0xff,0xff,0xff,0xff,0xff};
    static const unsigned char zero6[6]={0,0,0,0,0,0};
    for(int k=0;k<PROBE_SLOW;k++){
        if(g_sweep_cur<g_sweep_first || g_sweep_cur>g_sweep_last){
            g_sweep_cur=g_sweep_first;
            ping_start(PING_PER_TICK);
            g_next_sweep=now+SWEEP_IDLE_MS; return;
        }
        unsigned int tip=htonl_u(g_sweep_cur);
        g_sweep_cur++;
        if(tip==g_myip) continue;
        send_arp(1,bcastmac,g_myip,g_mymac,tip,zero6);
    }
}

static void enrich_tick(unsigned long now){
    if(now<g_next_enrich) return;
    g_next_enrich=now+ENRICH_MS;
    int active = g_scan_on || now<g_pass_until;
    if(active && g_enrich && g_nhost>0){
        for(int k=0;k<ENRICH_PER;k++){
            struct host *h=&g_hosts[(g_enrich_i++)%g_nhost];
            if(g_ns>=0) nbns_probe(g_ns,h->ip);
            if(g_ic>=0) icmp_echo(g_ic,h->ip,g_icmp_id);
            if(g_md>=0 && !h->name[0]) mdns_reverse(g_md,h->ip);
        }
    }
    for(int i=0;i<g_nhost;i++){
        const char *v=vendor_of(g_hosts[i].mac);
        if(v&&v[0]&&!g_hosts[i].vendor[0]) snprintf(g_hosts[i].vendor,sizeof g_hosts[i].vendor,"%s",v);
        char saved[64];
        if(!g_hosts[i].name[0] && name_lookup(g_hosts[i].mac,saved,sizeof saved)){
            snprintf(g_hosts[i].name,sizeof g_hosts[i].name,"%s",saved);
            g_hosts[i].name_src=SRC_USER;
        }
    }
}

static void drain_arp(void){
    for(int i=0;i<256 && recv_arp(0);i++){}
}

/* pacing */
static void bucket_refill(void){
    unsigned long now=now_ms();
    if(!g_bucket_ms) g_bucket_ms=now;
    double dt=(double)(now-g_bucket_ms)/1000.0;
    g_bucket_ms=now;
    g_bucket += dt*(double)g_rate_pps;
    if(g_bucket> (double)g_rate_pps*2) g_bucket=(double)g_rate_pps*2;
}
static int bucket_take(int frames){
    if(g_bucket<(double)frames) return 0;
    g_bucket-=(double)frames;
    return 1;
}

/* the derived cut set + wire work */
static void poison_refresh(unsigned long now){
    for(int i=0;i<g_nhost;i++){
        struct host *h=&g_hosts[i];
        int want = action_wants(h) && h->ip!=g_gwip && h->ip!=g_myip;
        if(want){ h->held=1; h->cut=1; }
        else if(h->held){ h->held=0; h->cut=0; }
        if(h->held && (now-h->last_ms)>=g_interval_ms && bucket_take(2)){
            poison(h); h->last_ms=now; g_frames+=2;
        }
    }
}

/* request dispatch */
static const char *host_state(const struct host *h){
    return h->held ? "held" : "idle";
}
static void host_json(jbuf *o,const struct host *h){
    char mac[20]; mac_str(h->mac,mac);
    struct in_addr a; a.s_addr=h->ip;
    jb_raw(o,"{\"ip\":"); jb_puts(o,inet_ntoa(a));
    jb_raw(o,",\"mac\":"); jb_puts(o,mac);
    jb_raw(o,",\"name\":"); jb_puts(o,h->name);
    jb_raw(o,",\"brand\":"); jb_puts(o,h->vendor);
    jb_raw(o,",\"state\":"); jb_puts(o,host_state(h));
    jb_raw(o,",\"last_ms\":"); jb_printf(o,"%lu",h->last_ms);
    jb_raw(o,",\"ttl\":"); jb_printf(o,"%d",h->ttl);
    jb_raw(o,",\"ip6\":"); jb_puts(o,h->ip6);
    unsigned long nw=now_ms();
    jb_raw(o,",\"on\":"); jb_raw(o,(h->seen_ms && (nw-h->seen_ms)<HOST_ON_MS)?"true":"false");
    jb_raw(o,",\"seen_s\":");
    if(h->seen_ms) jb_printf(o,"%lu",(nw-h->seen_ms)/1000);
    else jb_raw(o,"-1");
    jb_raw(o,",\"tags\":[");
    char t[64]; host_tags(h,t,sizeof t);
    int first=1; char *p=t;
    while(p&&*p){ char *c=strchr(p,','); if(c)*c=0;
        if(!first) jb_raw(o,","); jb_raw(o,"\""); jb_raw(o,p); jb_raw(o,"\""); first=0;
        p=c?c+1:NULL; }
    jb_raw(o,"]}");
}

static int host_matches_state(const struct host *h,const char *state){
    if(!state||!state[0]||!strcmp(state,"all")) return 1;
    if(!strcmp(state,"held")) return h->held!=0;
    if(!strcmp(state,"idle")) return !h->held;
    return 1;
}

static void dispatch(const char *line, jbuf *o){
    jval *req=jparse(line);
    char cmd[64];
    snprintf(cmd,sizeof cmd,"%s", req?jstr(jget(req,"cmd")):"");
    const char *sel = jget(req,"sel")&&jget(req,"sel")->t==JSTR?jstr(jget(req,"sel")):NULL;
    const char *state=jget(req,"state")&&jget(req,"state")->t==JSTR?jstr(jget(req,"state")):NULL;
    jval *idv=jget(req,"id");
    int has_id = idv && idv->t==JNUM;
    int id = has_id?(int)jnum(idv):-1;
    const char *value=jget(req,"value")&&jget(req,"value")->t==JSTR?jstr(jget(req,"value")):NULL;

    jbuf r; jb_init(&r);           /* result body */
    const char *err=NULL;

    if(!cmd[0]) err="no command";

    else if(!strcmp(cmd,"ping")) jb_raw(&r,"{}");

    else if(!strcmp(cmd,"status")){
        char ip[32],gw[32],gm[20];
        struct in_addr a; a.s_addr=g_myip; snprintf(ip,sizeof ip,"%s",inet_ntoa(a));
        a.s_addr=g_gwip; snprintf(gw,sizeof gw,"%s",inet_ntoa(a));
        mac_str(g_gwmac,gm);
        jb_raw(&r,"{\"iface\":"); jb_puts(&r,g_ifname);
        jb_raw(&r,",\"myip\":");  jb_puts(&r,ip);
        jb_raw(&r,",\"gw\":");    jb_puts(&r,gw);
        jb_raw(&r,",\"gwmac\":"); jb_puts(&r,gm);
        jb_raw(&r,",\"hosts\":"); jb_printf(&r,"%d",g_nhost);
        jb_raw(&r,",\"frames\":"); jb_printf(&r,"%lu",g_frames);
        jb_raw(&r,",\"drops\":"); jb_printf(&r,"%lu",g_drops);
        jb_raw(&r,",\"scan_paused\":"); jb_raw(&r,g_scan_on?"false":"true");
        jb_raw(&r,",\"actions\":[");
        int first=1;
        for(int i=0;i<MAX_ACTION;i++){
            struct action *act=action_at(i); if(!act) continue;
            int m=0; for(int k=0;k<g_nhost;k++) if(sel_match(&g_hosts[k],act->sel)) m++;
            if(!first) jb_raw(&r,",");
            jb_raw(&r,"{\"id\":"); jb_printf(&r,"%d",act->id);
            jb_raw(&r,",\"sel\":"); jb_puts(&r,act->sel);
            jb_raw(&r,",\"matched\":"); jb_printf(&r,"%d",m);
            jb_raw(&r,",\"age_s\":"); jb_printf(&r,"%lu",(now_ms()-act->born_ms)/1000);
            jb_raw(&r,",\"interval_ms\":"); jb_printf(&r,"%lu",g_interval_ms);
            jb_raw(&r,"}");
            first=0;
        }
        jb_raw(&r,"]}");
    }

    else if(!strcmp(cmd,"list")){
        int c=0;
        for(int i=0;i<g_nhost;i++) if(host_matches_state(&g_hosts[i],state)&&sel_match(&g_hosts[i],sel)) c++;
        jb_raw(&r,"{\"count\":"); jb_printf(&r,"%d,\"hosts\":[",c);
        int first=1;
        for(int i=0;i<g_nhost;i++){
            if(!host_matches_state(&g_hosts[i],state)) continue;
            if(!sel_match(&g_hosts[i],sel)) continue;
            if(!first){ jb_raw(&r,","); }
            host_json(&r,&g_hosts[i]); first=0;
        }
        jb_raw(&r,"]}");
    }

    else if(!strcmp(cmd,"cut")){
        if(sel && !sel_valid(sel)) err="bad selector";
        else {
            if(!(g_gwmac[0]||g_gwmac[1])) load_gwmac();
            if(g_do_v6 && !g_v6_ok) g_v6_ok = router_ll_from_route(g_router_ll);
            int aid=action_add(sel);
            if(aid<0) err="too many actions";
            else {
                int m=0; for(int i=0;i<g_nhost;i++) if(sel_match(&g_hosts[i],sel)) m++;
                jb_raw(&r,"{\"action_id\":"); jb_printf(&r,"%d",aid);
                jb_raw(&r,",\"matched\":"); jb_printf(&r,"%d",m); jb_raw(&r,"}");
            }
        }
    }

    else if(!strcmp(cmd,"stop")){
        int rep=0; jb_raw(&r,"{\"stopped\":["); int first=1;
        if(has_id){
            if(action_stop_id(id)){ jb_printf(&r,"%d",id); first=0; }
            else err="no such action";
        } else {
            for(int i=0;i<MAX_ACTION;i++){
                struct action *a=action_at(i); if(!a) continue;
                if(sel && strcmp(a->sel,sel)) continue;
                if(!first) jb_raw(&r,",");
                jb_printf(&r,"%d",a->id); first=0; a->active=0;
            }
        }
        if(!err){
            for(int i=0;i<g_nhost;i++) if(g_hosts[i].held && !action_wants(&g_hosts[i])) rep++;
            jb_raw(&r,"],\"released\":"); jb_printf(&r,"%d",rep); jb_raw(&r,"}");
        }
    }

    else if(!strcmp(cmd,"stopall")){
        int ids[MAX_ACTION],n=0;
        for(int i=0;i<MAX_ACTION;i++){ struct action *a=action_at(i); if(a) ids[n++]=a->id; }
        action_stop_all();
        jb_raw(&r,"{\"stopped\":[");
        for(int i=0;i<n;i++){ if(i) jb_raw(&r,","); jb_printf(&r,"%d",ids[i]); }
        int rep=0; for(int i=0;i<g_nhost;i++) if(g_hosts[i].held) rep++;
        jb_raw(&r,"],\"released\":"); jb_printf(&r,"%d",rep); jb_raw(&r,"}");
    }

    else if(!strcmp(cmd,"resume")){
        if(sel && !sel_valid(sel)) err="bad selector";
        else {
            int stopped=0;
            for(int i=0;i<MAX_ACTION;i++){
                struct action *a=action_at(i); if(!a) continue;
                int hit=0;
                for(int j=0;j<g_nhost && !hit;j++)
                    if(sel_match(&g_hosts[j],sel) && sel_match(&g_hosts[j],a->sel)) hit=1;
                if(hit){ a->active=0; stopped++; }
            }
            int n=0;
            for(int i=0;i<g_nhost;i++){
                if(!sel_match(&g_hosts[i],sel)) continue;
                if(!g_hosts[i].held) continue;
                g_hosts[i].held=0; g_hosts[i].cut=0; n++;
            }
            jb_raw(&r,"{\"released\":"); jb_printf(&r,"%d",n);
            jb_raw(&r,",\"stopped\":"); jb_printf(&r,"%d",stopped); jb_raw(&r,"}");
        }
    }

    else if(!strcmp(cmd,"scan")){
        open_discovery();
        g_browse_stage=-1;
        g_sweep_quiet=1; arp_sweep(); g_sweep_quiet=0;
        ping_start(0);
        if(g_dn>=0) dns_ptr_send(g_dn);
        unsigned long ts=now_ms();
        g_pass_until=ts+SCAN_WINDOW_MS;
        g_disc_off=ts+SCAN_WINDOW_MS+500;
        int alive=0; for(int i=0;i<g_nhost;i++) if(g_hosts[i].seen_ms && (ts-g_hosts[i].seen_ms)<HOST_ON_MS) alive++;
        jb_raw(&r,"{\"hosts\":"); jb_printf(&r,"%d",g_nhost);
        jb_raw(&r,",\"on\":"); jb_printf(&r,"%d",alive);
        jb_raw(&r,",\"frames\":"); jb_printf(&r,"%d",(int)g_frames); jb_raw(&r,"}");
    }

    else if(!strcmp(cmd,"scanpause")){ g_scan_on=0; g_disc_off=0; close_discovery(); jb_raw(&r,"{}"); }
    else if(!strcmp(cmd,"scanresume")){ open_discovery(); g_scan_on=1; jb_raw(&r,"{}"); }

    else if(!strcmp(cmd,"setname")){
        if(!value||!strchr(value,'=')) err="expected mac=name";
        else {
            char buf[160]; snprintf(buf,sizeof buf,"%s",value);
            char *eq=strchr(buf,'='); *eq=0;
            unsigned char mac[6];
            if(!parse_mac(buf,mac)) err="bad mac";
            else {
                name_set(mac,eq+1);
                for(int i=0;i<g_nhost;i++) if(!memcmp(g_hosts[i].mac,mac,6))
                    host_set_name(i,eq+1,SRC_USER);
                jb_raw(&r,"{}");
            }
        }
    }

    else if(!strcmp(cmd,"config")){
        if(value){
            char buf[160]; snprintf(buf,sizeof buf,"%s",value);
            char *eq=strchr(buf,'=');
            if(eq){
                *eq=0; const char *v=eq+1;
                if(!strcmp(buf,"interval_ms")){ long x=atol(v); if(x>=INTERVAL_MIN_MS) g_interval_ms=(unsigned long)x; }
                else if(!strcmp(buf,"rate_pps")){ int x=atoi(v); if(x>=1) g_rate_pps=x; }
                else if(!strcmp(buf,"do_v4")) g_do_v4=truthy(v);
                else if(!strcmp(buf,"do_v6")) g_do_v6=truthy(v);
                else if(!strcmp(buf,"scan_paused")){ g_scan_on = truthy(v)?0:1;
                    if(g_scan_on) open_discovery(); else { g_disc_off=0; close_discovery(); } }
                else if(!strcmp(buf,"scan_speed")){ g_scan_on = strcmp(v,"off")?1:0;
                    if(g_scan_on) open_discovery(); else { g_disc_off=0; close_discovery(); } }
            }
        }
        char fm[20]; mac_str(g_fake_mac,fm);
        jb_raw(&r,"{\"config\":{\"interval_ms\":"); jb_printf(&r,"%lu",g_interval_ms);
        jb_raw(&r,",\"rate_pps\":"); jb_printf(&r,"%d",g_rate_pps);
        jb_raw(&r,",\"do_v4\":"); jb_raw(&r,g_do_v4?"true":"false");
        jb_raw(&r,",\"do_v6\":"); jb_raw(&r,g_do_v6?"true":"false");
        jb_raw(&r,",\"scan_paused\":"); jb_raw(&r,g_scan_on?"false":"true");
        jb_raw(&r,",\"fake_mac\":"); jb_puts(&r,fm);
        jb_raw(&r,"}}");
    }

    else if(!strcmp(cmd,"shutdown")){ g_stop=1; jb_raw(&r,"{}"); }

    else err="unknown command";

    /* one envelope, always well formed */
    jb_raw(o,"{\"v\":1,\"ok\":"); jb_raw(o,err?"false":"true");
    jb_raw(o,",\"cmd\":"); jb_puts(o,cmd);
    jb_raw(o,",\"err\":"); if(err) jb_puts(o,err); else jb_raw(o,"null");
    jb_raw(o,",\"result\":"); jb_raw(o, err||!r.b ? "{}" : r.b);
    jb_raw(o,"}");
    jb_free(&r);
    if(req) jfree(req);
}

/* connections */
static void conn_close(int i){
    if(conns[i].fd>=0){ epoll_ctl(g_ep,EPOLL_CTL_DEL,conns[i].fd,NULL); close(conns[i].fd); }
    conns[i].fd=-1; conns[i].n=0;
}
static int conn_slot(void){
    for(int i=0;i<MAXCONN;i++) if(conns[i].fd<0) return i;
    return -1;
}
static void conn_read(int i){
    struct conn *c=&conns[i];
    ssize_t r=read(c->fd,c->buf+c->n,(size_t)(sizeof c->buf-1-c->n));
    if(r<0){
        if(errno==EAGAIN||errno==EWOULDBLOCK) return;   /* not here yet */
        conn_close(i); return;
    }
    if(r==0){ conn_close(i); return; }
    c->n+=(int)r; c->buf[c->n]=0;
    char *nl=memchr(c->buf,'\n',(size_t)c->n);
    if(!nl) return;
    *nl=0;
    jbuf o; jb_init(&o);
    dispatch(c->buf,&o);
    if(o.b){ ssize_t w=write(c->fd,o.b,o.n); (void)w; write(c->fd,"\n",1); }
    jb_free(&o);
    conn_close(i);
}
static void rpc_accept(void){
    for(;;){
        int fd=accept(g_lfd,NULL,NULL);
        if(fd<0) break;
        int fl=fcntl(fd,F_GETFL,0); fcntl(fd,F_SETFL,fl|O_NONBLOCK);
        int i=conn_slot();
        if(i<0){ close(fd); continue; }
        conns[i].fd=fd; conns[i].n=0; conns[i].deadline=now_ms()+1000;
        struct epoll_event ev; memset(&ev,0,sizeof ev);
        ev.events=EPOLLIN; ev.data.u32=(unsigned)i+1000;   /* 1000+ => conn index */
        epoll_ctl(g_ep,EPOLL_CTL_ADD,fd,&ev);
        conn_read(i);
    }
}

/* setup / teardown */
static int add_fd(int fd,unsigned tag){
    if(fd<0) return -1;
    struct epoll_event ev; memset(&ev,0,sizeof ev);
    ev.events=EPOLLIN; ev.data.u32=(unsigned)tag;
    return epoll_ctl(g_ep,EPOLL_CTL_ADD,fd,&ev);
}

static void set_nb(int fd){
    if(fd<0) return;
    int fl=fcntl(fd,F_GETFL,0); fcntl(fd,F_SETFL,fl|O_NONBLOCK);
}

static int open_discovery(void){
    if(g_md>=0 || g_ns>=0 || g_ic>=0 || g_dh>=0) return 0;   /* already open */
    g_md = mdns_open();
    g_ns = socket(AF_INET,SOCK_DGRAM,0);
    g_ic = icmp_open();
    g_dh = dhcp_sock_open();
    g_sd = ssdp_open();
    g_dn = dns_ptr_open();
    set_nb(g_md); set_nb(g_ns); set_nb(g_ic); set_nb(g_dh); set_nb(g_sd); set_nb(g_dn);
    add_fd(g_md,3); add_fd(g_ns,4); add_fd(g_ic,5); add_fd(g_dh,6);
    add_fd(g_sd,7); add_fd(g_dn,8);
    return 0;
}
static void close_discovery(void){
    if(g_sd>=0){ ssdp_finish(); close(g_sd); g_sd=-1; }
    if(g_dn>=0){ close(g_dn); g_dn=-1; }
    if(g_md>=0){ close(g_md); g_md=-1; }
    if(g_ns>=0){ close(g_ns); g_ns=-1; }
    if(g_ic>=0){ close(g_ic); g_ic=-1; }
    if(g_dh>=0){ close(g_dh); g_dh=-1; }
}

int server_run(void){
    setvbuf(stdout,NULL,_IOLBF,0);
    actions_init();
    install_signals();
    g_loop_active=1;
    g_icmp_id=(unsigned short)(getpid()&0xffff);

    int lk=lock_acquire();
    if(lk!=0) return 1;

    int sd=socket(AF_UNIX,SOCK_STREAM,0);
    if(sd<0){ perror("socket"); lock_release(); return 1; }
    int lfl=fcntl(sd,F_GETFL,0); fcntl(sd,F_SETFL,lfl|O_NONBLOCK);
    unlink(SOCK_PATH);
    struct sockaddr_un un; memset(&un,0,sizeof un);
    un.sun_family=AF_UNIX;
    snprintf(un.sun_path,sizeof un.sun_path,"%s",SOCK_PATH);
    if(bind(sd,(struct sockaddr*)&un,sizeof un)<0){ perror("bind"); lock_release(); return 1; }
    chmod(SOCK_PATH,0600);
    /* When started with sudo, hand the control socket to the invoking user so
       the TUI/CLI work without a second sudo. The endpoint is still private. */
    {
        const char *su=getenv("SUDO_UID"), *sg=getenv("SUDO_GID");
        if(su){ uid_t u=(uid_t)atoi(su); gid_t g=(gid_t)(sg?atoi(sg):(int)u);
                if(chown(SOCK_PATH,u,g)!=0) perror("chown socket"); }
    }
    listen(sd,8);
    g_lfd=sd;

    if(setup_network()!=0){ fprintf(stderr,"lanternet: no usable interface\n"); lock_release(); unlink(SOCK_PATH); return 1; }

    g_ep=epoll_create1(0);

    struct epoll_event ev; memset(&ev,0,sizeof ev);
    ev.events=EPOLLIN;
    ev.data.u32=1; epoll_ctl(g_ep,EPOLL_CTL_ADD,g_lfd,&ev);
    add_fd(g_sock,2);
    for(int i=0;i<MAXCONN;i++) conns[i].fd=-1;

    if(g_dry) fprintf(stderr,"DRY MODE: no packets will be sent\n");
    struct in_addr a; a.s_addr=g_myip;
    printf("lanternet server up: iface %s ip %s hosts %d\n",
            g_ifname, inet_ntoa(a), g_nhost);

    unsigned long now=now_ms();
    g_next_merge=now+5000; g_next_hb=now+10000; g_next_keep=now+1000; g_next_browse=now+2000;

    struct epoll_event evs[16];
    while(!g_stop){
        int n=epoll_wait(g_ep,evs,16,TICK_MS);
        for(int i=0;i<n;i++){
            unsigned tag=evs[i].data.u32;
            if(tag>=1000){ conn_read((int)tag-1000); }
            else if(tag==1) rpc_accept();
            else if(tag==2) drain_arp();
            else if(tag==3){ for(int k=0;k<64;k++){ unsigned char b[4096];
                    ssize_t r=recv(g_md,b,sizeof b,0);
                    if(r<=0) break; mdns_parse(b,(int)r); } }
            else if(tag==4){ for(int k=0;k<64;k++){ unsigned char b[1024];
                    struct sockaddr_in fr; socklen_t fl=sizeof fr;
                    ssize_t r=recvfrom(g_ns,b,sizeof b,0,(struct sockaddr*)&fr,&fl);
                    if(r<=0) break; nbns_parse(b,(int)r,fr.sin_addr.s_addr); } }
            else if(tag==5){ icmp_handle(g_ic); }
            else if(tag==6){ dhcp_recv(g_dh); }
            else if(tag==7){ ssdp_recv(g_sd); }
            else if(tag==8){ dns_ptr_recv(g_dn); }
        }

        now=now_ms();
        bucket_refill();
        scan_tick();
        ping_tick();
        drain_arp();
        enrich_tick(now);
        if(g_disc_off && now>=g_disc_off && !g_scan_on){ close_discovery(); g_disc_off=0; }
        poison_refresh(now);

        if(now>=g_next_keep){ if(actions_active()) self_keepalive(); g_next_keep=now+1000; }
        if(now>=g_next_merge){ merge_arp_file(); merge_neigh(); merge_dhcp_leases(); cache_load(); g_next_merge=now+5000; }
        if(now>=g_next_hb){ lock_write(); g_next_hb=now+10000; }
        if(g_guard_pid>0){
            char gp[64]; snprintf(gp,sizeof gp,"/proc/%d",g_guard_pid);
            if(access(gp,F_OK)!=0){ fprintf(stderr,"lanternet: guarded process %d is gone, stopping\n",g_guard_pid); g_stop=1; }
        }
        if(now>=g_next_browse){
            if(g_md>=0 && g_enrich && (g_scan_on || now<g_pass_until)){
                if(g_browse_stage<0){ mdns_browse_stage(g_md,0); g_browse_stage=0; g_next_browse=now+1500; }
                else if(g_browse_stage<3){ g_browse_stage++; mdns_browse_stage(g_md,g_browse_stage); g_next_browse=now+1500; }
                else { mdns_browse_finish(); g_browse_stage=-1; g_next_browse=now+20000; }
            } else g_next_browse=now+20000;
        }
    }

    printf("lanternet: stopping...\n");
    fflush(stdout);
    cache_save();
    if(g_md>=0) close(g_md);
    if(g_ns>=0) close(g_ns);
    if(g_ic>=0) close(g_ic);
    if(g_dh>=0) close(g_dh);
    if(g_sock>=0) close(g_sock);
    if(g_lfd>=0) close(g_lfd);
    unlink(SOCK_PATH);
    lock_release();
    return 0;
}
