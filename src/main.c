/* main.c - globals, argument parsing, and entry point */
#include "lanternet.h"

/* globals */
struct host g_hosts[MAXHOST];
int g_nhost=0;
int g_sock=-1, g_ifidx=-1;
unsigned char g_mymac[6], g_gwmac[6], g_router_ll[16];
unsigned int g_myip=0, g_gwip=0, g_mask=0;
char g_ifname[64]="";
int g_do_v4=1, g_do_v6=1, g_v6_ok=0, g_dry=0, g_use_fake=0, g_json=0;
int g_sweep_quiet=0;
int g_guard_pid=0;
unsigned long g_interval_ms=INTERVAL_MS;
unsigned char g_fake_mac[6];
int g_rate_pps=400;
int g_scan_speed=0;          /* 0 slow, 1 fast, 2 paused */
unsigned long g_frames=0;
unsigned long g_drops=0;

#define ARGS_MAX 8

static int mac_is_set(const unsigned char *m){
    return m[0]|m[1]|m[2]|m[3]|m[4]|m[5];
}

static void random_local_mac(unsigned char *m){
    srand((unsigned)time(NULL) ^ (unsigned)getpid());
    for(int k=0;k<6;k++) m[k]=(unsigned char)(rand()&0xff);
    m[0]=(m[0]&0xfe)|0x02;
}

static void parse_args(int argc,char **argv,const char **cmd,const char **arg,int *narg){
    for(int i=1;i<argc;i++){
        const char *a=argv[i];
        if(!strcmp(a,"--v4")||!strcmp(a,"-4")) g_do_v6=0;
        else if(!strcmp(a,"--v6")||!strcmp(a,"-6")) g_do_v4=0;
        else if(!strcmp(a,"--dry")) g_dry=1;
        else if(!strcmp(a,"--json")) g_json=1;
        else if(!strcmp(a,"--guard") && i+1<argc) g_guard_pid=atoi(argv[++i]);
        else if(!strcmp(a,"--gw") && i+1<argc) inet_pton(AF_INET,argv[++i],&g_gwip);
        else if(!strcmp(a,"--rate") && i+1<argc) g_rate_pps=atoi(argv[++i]);
        else if(!strcmp(a,"--interval") && i+1<argc){
            long v=atol(argv[++i]);
            if(v>=INTERVAL_MIN_MS) g_interval_ms=(unsigned long)v;
        }
        else if(!strcmp(a,"--fake-mac")){
            g_use_fake=1;
            if(i+1<argc && strchr(argv[i+1],':') && parse_mac(argv[i+1],g_fake_mac)){
                g_fake_mac[0]=(g_fake_mac[0]&0xfe)|0x02; i++;
            }
        }
        else if(*cmd==NULL && a[0]!='-') *cmd=a;
        else if(*narg<ARGS_MAX) arg[(*narg)++]=a;
    }
}

/* pull "k=v"-style options out of the arg list; returns count of bare words */
static int split_opts(const char *arg[],int narg,const char **bare,int *nbare,
                      const char **state,int *id){
    *nbare=0; *state=NULL; *id=-1;
    for(int i=0;i<narg;i++){
        if(!strncmp(arg[i],"state=",6)) *state=arg[i]+6;
        else if(!strncmp(arg[i],"id=",3)) *id=atoi(arg[i]+3);
        else if(*nbare<4) bare[(*nbare)++]=arg[i];
    }
    return *nbare;
}

int main(int argc,char **argv){
    if(argc<2){ client_usage(); return 0; }

    const char *cmd=NULL, *arg[ARGS_MAX]; int narg=0;
    parse_args(argc,argv,&cmd,arg,&narg);
    if(g_use_fake && !mac_is_set(g_fake_mac)) random_local_mac(g_fake_mac);
    if(!cmd){ client_usage(); return 0; }

    if(!strcmp(cmd,"start")||!strcmp(cmd,"server")||!strcmp(cmd,"serve"))
        return server_run();
    if(!strcmp(cmd,"tui"))
        return tui_run();

    install_signals();

    const char *bare[4]; int nbare; const char *state; int id;
    split_opts(arg,narg,bare,&nbare,&state,&id);
    const char *sel = nbare>0 ? bare[0] : NULL;
    const char *value = NULL;
    int has_id = 0;

    /* command aliases + arity mapping */
    if(!strcmp(cmd,"panic")) cmd="stopall";
    else if(!strcmp(cmd,"stop") && id<0 && nbare==0 && !state) { /* plain `stop` = shutdown */ }

    if(!strcmp(cmd,"setname")){
        if(nbare<2){ fprintf(stderr,"usage: lanternet setname <mac> <name>\n"); return 2; }
        static char kv[160]; snprintf(kv,sizeof kv,"%s=%s",bare[0],bare[1]);
        value=kv; sel=NULL;
    } else if(!strcmp(cmd,"config")){
        value = nbare>0 ? bare[0] : NULL;
    } else if(id>=0){ has_id=1; }

    return client_send(cmd,sel,state,has_id,id,value,g_json);
}
