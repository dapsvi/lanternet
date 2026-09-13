/* main.c - the globals, argument parsing, and the entry point */
#include "lanternet.h"

/* globals */
struct host g_hosts[MAXHOST];
int g_nhost=0;
int g_sock=-1, g_ifidx=-1;
unsigned char g_mymac[6], g_gwmac[6], g_router_ll[16];
unsigned int g_myip=0, g_gwip=0, g_mask=0;
char g_ifname[64]="";
int g_do_v4=1, g_do_v6=1, g_v6_ok=0, g_scan_all=0, g_dry=0, g_use_fake=0, g_json=0;
int g_guard_pid=0;
unsigned char g_fake_mac[6];

#define ARGS_MAX 8

static int mac_is_set(const unsigned char *m){
    return m[0]|m[1]|m[2]|m[3]|m[4]|m[5];
}

static void random_local_mac(unsigned char *m){
    srand((unsigned)time(NULL) ^ (unsigned)getpid());
    for(int k=0;k<6;k++) m[k]=(unsigned char)(rand()&0xff);
    m[0]=(m[0]&0xfe)|0x02;                     /* locally administered, unicast */
}

/* flags may appear anywhere; the first bare word is the command */
static void parse_args(int argc,char **argv,const char **cmd,const char **arg,int *narg){
    for(int i=1;i<argc;i++){
        const char *a=argv[i];
        if(!strcmp(a,"--v4")||!strcmp(a,"-4")) g_do_v6=0;
        else if(!strcmp(a,"--v6")||!strcmp(a,"-6")) g_do_v4=0;
        else if(!strcmp(a,"--all")) g_scan_all=1;
        else if(!strcmp(a,"--dry")) g_dry=1;
        else if(!strcmp(a,"--json")) g_json=1;
        else if(!strcmp(a,"--guard") && i+1<argc) g_guard_pid=atoi(argv[++i]);
        else if(!strcmp(a,"--gw") && i+1<argc) inet_pton(AF_INET,argv[++i],&g_gwip);
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

int main(int argc,char **argv){
    if(argc<2){ cli_usage(); return 0; }

    const char *cmd=NULL, *arg[ARGS_MAX]; int narg=0;
    parse_args(argc,argv,&cmd,arg,&narg);
    if(g_use_fake && !mac_is_set(g_fake_mac)) random_local_mac(g_fake_mac);
#ifdef LANTERNET_APP
    app_install_signals();
#endif

    return cli_run(cmd,narg,arg);
}
