/* client.c - Builds a request, talks to the server over the unix socket, and prints the reply */
#include "lanternet.h"
#include "jsonlite.h"
#include <sys/un.h>

char g_rpc_err[160]="";

char *rpc_raw(const char *req){
    g_rpc_err[0]=0;
    int fd=socket(AF_UNIX,SOCK_STREAM,0);
    if(fd<0){ snprintf(g_rpc_err,sizeof g_rpc_err,"socket: %s",strerror(errno)); return NULL; }
    struct sockaddr_un un; memset(&un,0,sizeof un);
    un.sun_family=AF_UNIX;
    snprintf(un.sun_path,sizeof un.sun_path,"%s",SOCK_PATH);
    int ok=0;
    for(int tries=0;tries<15;tries++){
        if(connect(fd,(struct sockaddr*)&un,sizeof un)==0){ ok=1; break; }
        if(errno!=ENOENT && errno!=ECONNREFUSED) break;
        struct timespec ts={0,200000000}; nanosleep(&ts,NULL);
    }
    if(!ok){ snprintf(g_rpc_err,sizeof g_rpc_err,"%s: %s",SOCK_PATH,strerror(errno)); close(fd); return NULL; }
    struct timeval tv={6,0}; setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);
    setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof tv);
    size_t L=strlen(req);
    if(write(fd,req,L)!=(ssize_t)L){ close(fd); return NULL; }
    if(write(fd,"\n",1)!=1){ close(fd); return NULL; }
    char *buf=NULL; size_t cap=0,n=0;
    for(;;){
        if(n+4096+1>cap){ cap=cap?cap*2:8192; buf=realloc(buf,cap); }
        ssize_t r=read(fd,buf+n,cap-n-1);
        if(r<0){ free(buf); close(fd); return NULL; }
        if(r==0) break;
        n+=(size_t)r; buf[n]=0;
        if(memchr(buf,'\n',n)) break;
    }
    close(fd);
    if(!buf) return NULL;
    buf[strcspn(buf,"\r\n")]=0;
    return buf;
}

static const char *mode="client";
void __client_mode_unused(void){ (void)mode; }

/* build the request object */
static char *build_req(const char *cmd,const char *sel,const char *state,
                       int has_id,int id,const char *value){
    jbuf j; jb_init(&j);
    jb_raw(&j,"{\"v\":1,\"cmd\":");
    jb_puts(&j,cmd);
    jb_raw(&j,",\"sel\":");
    if(sel) jb_puts(&j,sel); else jb_raw(&j,"null");
    jb_raw(&j,",\"state\":");
    if(state) jb_puts(&j,state); else jb_raw(&j,"null");
    jb_raw(&j,",\"id\":");
    if(has_id) jb_printf(&j,"%d",id); else jb_raw(&j,"null");
    jb_raw(&j,",\"value\":");
    if(value) jb_puts(&j,value); else jb_raw(&j,"null");
    jb_raw(&j,"}");
    return j.b;   /* caller frees */
}

static void print_table(jval *arr){
    int n=jlen(arr);
    printf("%-15s %-17s %-8s %-28s %s\n","IP","MAC","STATE","NAME","TAGS");
    for(int i=0;i<n;i++){
        jval *h=jat(arr,i);
        const char *nm=jstr(jget(h,"name"));
        const char *br=jstr(jget(h,"brand"));
        printf("%-15s %-17s %-8s %-28s ",
            jstr(jget(h,"ip")), jstr(jget(h,"mac")),
            jstr(jget(h,"state")), nm[0]?nm:br);
        jval *t=jget(h,"tags");
        for(int k=0;k<jlen(t);k++) printf("%s%s",k?",":"",jstr(jat(t,k)));
        printf("\n");
    }
    printf("%d device%s\n",n,n==1?"":"s");
}

static void print_actions(jval *acts){
    int n=jlen(acts);
    if(!n){ printf("(no live actions)\n"); return; }
    printf("%-4s %-8s %-6s %-30s %s\n","ID","AGE","MATCH","SELECTOR","INTERVAL");
    for(int i=0;i<n;i++){
        jval *a=jat(acts,i);
        printf("%-4.0f %-8.0f %-6.0f %-30s %.0fms\n",
            jnum(jget(a,"id")), jnum(jget(a,"age_s")), jnum(jget(a,"matched")),
            jstr(jget(a,"sel"))[0]?jstr(jget(a,"sel")):"*", jnum(jget(a,"interval_ms")));
    }
}

static void pretty(const char *cmd,jval *resp){
    jval *r=jget(resp,"result");
    if(!strcmp(cmd,"list")){ print_table(jget(r,"hosts")); }
    else if(!strcmp(cmd,"cut")){ printf("action %d started, matching %d device%s\n",
        (int)jnum(jget(r,"action_id")), (int)jnum(jget(r,"matched")),
        jnum(jget(r,"matched"))==1?"":"s"); }
    else if(!strcmp(cmd,"stop")){ printf("stopped %d action%s, releasing %d device%s\n",
        jlen(jget(r,"stopped")), jlen(jget(r,"stopped"))==1?"":"s",
        (int)jnum(jget(r,"released")), jnum(jget(r,"released"))==1?"":"s"); }
    else if(!strcmp(cmd,"stopall")){ printf("stopped %d action%s, releasing %d device%s\n",
        jlen(jget(r,"stopped")), jlen(jget(r,"stopped"))==1?"":"s",
        (int)jnum(jget(r,"released")), jnum(jget(r,"released"))==1?"":"s"); }
    else if(!strcmp(cmd,"resume")){ printf("releasing %d device%s\n",
        (int)jnum(jget(r,"released")), jnum(jget(r,"released"))==1?"":"s"); }
    else if(!strcmp(cmd,"scan")){ printf("scanned, %d device%s known, %d on\n",
        (int)jnum(jget(r,"hosts")), jnum(jget(r,"hosts"))==1?"":"s", (int)jnum(jget(r,"on"))); }
    else if(!strcmp(cmd,"status")){
        jval *spv=jget(r,"scan_paused"); int paused=spv&&spv->t==JBOOL&&spv->b;
        printf("iface %s  myip %s  gw %s (%s)\n",
            jstr(jget(r,"iface")), jstr(jget(r,"myip")),
            jstr(jget(r,"gw")), jstr(jget(r,"gwmac")));
        printf("devices %d  frames %d  drops %d  scanner %s\n",
            (int)jnum(jget(r,"hosts")), (int)jnum(jget(r,"frames")), (int)jnum(jget(r,"drops")),
            paused?"idle (no background traffic)":"running");
        print_actions(jget(r,"actions"));
    }
    else if(!strcmp(cmd,"config")){ printf("%s\n",jstr(jget(resp,"err"))); }
    else { printf("ok\n"); }
}

int client_send(const char *cmd,const char *sel,const char *state,
                int has_id,int id,const char *value,int print_json){
    char *req=build_req(cmd,sel,state,has_id,id,value);
    char *line=rpc_raw(req);
    free(req);
    if(!line){
        fprintf(stderr,"lanternet: %s\n", g_rpc_err[0]?g_rpc_err:"cannot reach server");
        if(strstr(g_rpc_err,"Permission"))
            fprintf(stderr,"  the control socket is root-only; run the client as root (sudo)\n");
        else if(strstr(g_rpc_err,"No such"))
            fprintf(stderr,"  start it with:  sudo lanternet start\n");
        return 1;
    }
    if(print_json){ printf("%s\n",line); free(line); return 0; }
    jval *resp=jparse(line);
    if(!resp){ printf("%s\n",line); free(line); return 0; }
    free(line);
    jval *okv=jget(resp,"ok");
    int ok = okv && okv->t==JBOOL && okv->b;
    if(!ok){
        const char *e=jstr(jget(resp,"err"));
        fprintf(stderr,"lanternet: %s\n", e[0]?e:"error");
        jfree(resp); return 1;
    }
    pretty(cmd,resp);
    jfree(resp);
    return 0;
}

int client_usage(void){
    printf(
"lanternet %s\n"
"\n"
"  lanternet start                 start the server (needs root)\n"
"  lanternet tui                   live terminal UI\n"
"  lanternet status                server + action overview\n"
"  lanternet list [selector]       devices found by the scanner\n"
"  lanternet scan [selector]       one immediate sweep (the only active traffic by default)\n"
"  lanternet scanpause|scanresume  off/on for continuous background discovery\n"
"  lanternet cut [selector]        cut every matching device (no selector = all)\n"
"  lanternet stop <id|selector>    stop action(s)\n"
"  lanternet stopall               stop everything\n"
"  lanternet resume [selector]     release matching devices\n"
"  lanternet setname <mac> <name>  give a device a permanent name\n"
"  lanternet config [key=val]      read or set tunables\n"
"  lanternet shutdown              stop the server\n"
"\n"
"selectors match ip, mac, name or tags; combine with && || ! and quote them.\n"
"  lanternet cut 'random-mac && !tag:gateway'      every randomised device\n"
"\n",LANTERNET_VERSION);
    return 0;
}
