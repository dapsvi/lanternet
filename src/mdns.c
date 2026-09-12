/* mdns.c - mDNS: A/PTR parsing, reverse lookups and service browsing */
#include "lanternet.h"

#define MDNS_MAXTYPE 24
#define MDNS_MAXINST 64
#define MDNS_MAXA    128

struct mdns_inst { char name[128]; char full[160]; char host[128]; };


int mdns_open(void){
    int s=socket(AF_INET,SOCK_DGRAM,0);
    if(s<0) return -1;
    int on=1; setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&on,sizeof on);
    struct sockaddr_in a; memset(&a,0,sizeof a);
    a.sin_family=AF_INET; a.sin_port=htons(5353); a.sin_addr.s_addr=htonl(INADDR_ANY);
    if(bind(s,(struct sockaddr*)&a,sizeof a)<0){ close(s); return -1; }
    struct ip_mreq m; memset(&m,0,sizeof m);
    inet_pton(AF_INET,"224.0.0.251",&m.imr_multiaddr);
    m.imr_interface.s_addr=g_myip;
    setsockopt(s,IPPROTO_IP,IP_ADD_MEMBERSHIP,&m,sizeof m);
    unsigned char ttl=255; setsockopt(s,IPPROTO_IP,IP_MULTICAST_TTL,&ttl,sizeof ttl);
    in_addr_t ifa=g_myip; setsockopt(s,IPPROTO_IP,IP_MULTICAST_IF,&ifa,sizeof ifa);
    return s;
}

void mdns_reverse(int s, unsigned int ip){
    unsigned char b[512]; memset(b,0,sizeof b);
    unsigned int h=ntohl(ip);
    char rev[64];
    snprintf(rev,sizeof rev,"%u.%u.%u.%u.in-addr.arpa",
        h&0xff,(h>>8)&0xff,(h>>16)&0xff,(h>>24)&0xff);
    b[4]=0; b[5]=1;
    int o=dns_enc_name(b+12,sizeof b-12,rev);
    if(o<0) return;
    int q=12+o;
    b[q++]=0x00; b[q++]=12;    /* PTR */
    b[q++]=0x00; b[q++]=1;     /* IN */
    struct sockaddr_in d; memset(&d,0,sizeof d);
    d.sin_family=AF_INET; d.sin_port=htons(5353);
    inet_pton(AF_INET,"224.0.0.251",&d.sin_addr);
    sendto(s,b,q,0,(struct sockaddr*)&d,sizeof d);
}

void mdns_parse(const unsigned char *p,int n){
    if(n<12) return;
    int qd=(p[4]<<8)|p[5], an=(p[6]<<8)|p[7], off=12;
    for(int i=0;i<qd;i++){ off=dns_skip_name(p,n,off); if(off<0) return; off+=4; }
    for(int i=0;i<an && off+10<=n;i++){
        char owner[128]; off=dns_read_name(p,n,off,owner,sizeof owner);
        if(off<0||off+10>n) return;
        int type=(p[off]<<8)|p[off+1];
        off+=8;                                  /* type, class, ttl */
        int rdl=(p[off]<<8)|p[off+1]; off+=2;
        if(off+rdl>n) return;
        if(type==1 && rdl==4){                   /* A: owner -> ip */
            unsigned int ip; memcpy(&ip,p+off,4);
            int hi=find_host(ip);
            if(hi>=0 && !g_hosts[hi].name[0]){
                char nm[128]; snprintf(nm,sizeof nm,"%s",owner);
                char *dot=strstr(nm,".local"); if(dot) *dot=0;
                if(nm[0]) host_set_name(hi,nm,3);
            }
        } else if(type==12){                     /* PTR: reverse name -> target */
            char tgt[128]; dns_read_name(p,n,off,tgt,sizeof tgt);
            if(strstr(owner,".in-addr.arpa")){
                unsigned a=0,bb=0,c=0,d=0;
                if(sscanf(owner,"%u.%u.%u.%u",&a,&bb,&c,&d)==4){
                    unsigned int ip=htonl((d<<24)|(c<<16)|(bb<<8)|a);
                    int hi=find_host(ip);
                    if(hi>=0 && !g_hosts[hi].name[0]){
                        char *dot=strstr(tgt,".local"); if(dot) *dot=0;
                        if(tgt[0]) host_set_name(hi,tgt,3);
                    }
                }
            }
        }
        off+=rdl;
    }
}

static char           mdns_type[MDNS_MAXTYPE][128];

static int            mdns_ntype;

static struct mdns_inst mdns_inst[MDNS_MAXINST];

static int            mdns_ninst;

static char           mdns_aname[MDNS_MAXA][128];

static unsigned int   mdns_aip[MDNS_MAXA];

static int            mdns_na;

static void mdns_ingest(const unsigned char *p,int n){
    if(n<12) return;
    int qd=(p[4]<<8)|p[5], tot=((p[6]<<8)|p[7])+((p[8]<<8)|p[9])+((p[10]<<8)|p[11]);
    int off=12;
    for(int i=0;i<qd;i++){ off=dns_skip_name(p,n,off); if(off<0) return; off+=4; }
    for(int i=0;i<tot;i++){
        char owner[128];
        off=dns_read_name(p,n,off,owner,sizeof owner);
        if(off<0||off+10>n) return;
        int type=(p[off]<<8)|p[off+1];
        int rdl=(p[off+8]<<8)|p[off+9];
        off+=10;
        if(off+rdl>n) return;
        if(type==12){                                   /* PTR */
            char tgt[128]; dns_read_name(p,n,off,tgt,sizeof tgt);
            if(!strcasecmp(owner,"_services._dns-sd._udp.local")){
                if(mdns_ntype<MDNS_MAXTYPE) snprintf(mdns_type[mdns_ntype++],sizeof mdns_type[0],"%s",tgt);
            } else if(tgt[0]){
                int known=0;
                for(int k=0;k<mdns_ninst;k++) if(!strcmp(mdns_inst[k].full,tgt)){ known=1; break; }
                if(!known && mdns_ninst<MDNS_MAXINST){
                    struct mdns_inst *ni=&mdns_inst[mdns_ninst++];
                    snprintf(ni->full,sizeof ni->full,"%s",tgt);
                    snprintf(ni->name,sizeof ni->name,"%s",tgt);
                    char *dot=strstr(ni->name,"._");   /* drop the ._type._proto.local tail */
                    if(dot) *dot=0;
                }
            }
        } else if(type==33 && rdl>=6){                  /* SRV -> target host */
            char tgt[128]; dns_read_name(p,n,off+6,tgt,sizeof tgt);
            for(int k=0;k<mdns_ninst;k++) if(!strcmp(mdns_inst[k].full,owner)){
                if(!mdns_inst[k].host[0]) snprintf(mdns_inst[k].host,sizeof mdns_inst[0].host,"%s",tgt);
                break;
            }
        } else if(type==1 && rdl==4){                   /* A -> address */
            if(mdns_na<MDNS_MAXA){
                unsigned int ip; memcpy(&ip,p+off,4);
                snprintf(mdns_aname[mdns_na],sizeof mdns_aname[0],"%s",owner);
                mdns_aip[mdns_na]=ip; mdns_na++;
            }
        }
        off+=rdl;
    }
}

static void mdns_send(int s,const char *name,int type){
    unsigned char q[300]; memset(q,0,sizeof q);
    q[5]=1;
    int o=dns_enc_name((unsigned char*)q+12,sizeof q-16,name);
    if(o<0) return;
    int qn=12+o; q[qn++]=0; q[qn++]=(unsigned char)type; q[qn++]=0; q[qn++]=1;
    struct sockaddr_in d; memset(&d,0,sizeof d);
    d.sin_family=AF_INET; d.sin_port=htons(5353);
    inet_pton(AF_INET,"224.0.0.251",&d.sin_addr);
    sendto(s,q,qn,0,(struct sockaddr*)&d,sizeof d);
}

static void mdns_collect(int s,int ms){
    unsigned long end=now_ms()+(unsigned long)ms;
    while(now_ms()<end){
        struct timeval tv={0,100000};
        fd_set fds; FD_ZERO(&fds); FD_SET(s,&fds);
        if(select(s+1,&fds,NULL,NULL,&tv)<=0) continue;
        unsigned char b[4096];
        int n=recv(s,b,sizeof b,0);
        if(n>0) mdns_ingest(b,n);
    }
}

void mdns_browse(void){
    int s=mdns_open();
    if(s<0) return;

    mdns_send(s,"_services._dns-sd._udp.local",12);
    mdns_collect(s,600);
    int nt=mdns_ntype;
    for(int i=0;i<nt && i<12;i++) mdns_send(s,mdns_type[i],12);
    mdns_collect(s,1000);
    for(int i=0;i<mdns_ninst;i++){
        mdns_send(s,mdns_inst[i].full,33);
        mdns_send(s,mdns_inst[i].full,16);
    }
    mdns_collect(s,1000);
    for(int i=0;i<mdns_ninst;i++){
        if(!mdns_inst[i].host[0]) continue;
        mdns_send(s,mdns_inst[i].host,1);
    }
    mdns_collect(s,700);
    close(s);

    for(int i=0;i<mdns_ninst;i++){
        if(!mdns_inst[i].host[0]) continue;
        unsigned int ip=0; int found=0;
        for(int k=0;k<mdns_na;k++)
            if(!strcmp(mdns_aname[k],mdns_inst[i].host)){ ip=mdns_aip[k]; found=1; break; }
        if(!found) continue;
        int hi=find_host(ip);
        if(hi<0 || g_hosts[hi].name[0]) continue;
        char nm[128]; memcpy(nm,mdns_inst[i].name,sizeof nm); nm[sizeof nm-1]=0;
        char *us=strrchr(nm,'_');
        if(us && strlen(us+1)>=2 && strlen(us+1)<=5){
            int allnum=1; for(char *q=us+1;*q;q++) if(!isdigit((unsigned char)*q)) allnum=0;
            if(allnum) *us=0;
        }
        if(nm[0]) host_set_name(hi,nm,6);
    }
}
