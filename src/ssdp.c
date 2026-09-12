/* ssdp.c - SSDP/UPnP discovery and friendlyName fetch */
#include "lanternet.h"

static int xml_tag(const char *xml,const char *tag,char *out,int n){
    char open[48], close_[48];
    snprintf(open,sizeof open,"<%s>",tag);
    snprintf(close_,sizeof close_,"</%s>",tag);
    const char *p=find_ci(xml,open);
    if(!p) return 0;
    p+=strlen(open);
    const char *e=find_ci(p,close_);
    if(!e) return 0;
    int L=(int)(e-p); if(L>n-1) L=n-1;
    memcpy(out,p,L); out[L]=0;
    return out[0]!=0;
}

static int http_get(const char *ip,int port,const char *path,char *out,int cap){
    int fd=socket(AF_INET,SOCK_STREAM,0);
    if(fd<0) return 0;
    struct sockaddr_in d; memset(&d,0,sizeof d);
    d.sin_family=AF_INET; d.sin_port=htons((unsigned short)port);
    if(inet_pton(AF_INET,ip,&d.sin_addr)!=1){ close(fd); return 0; }
    int fl=fcntl(fd,F_GETFL,0); fcntl(fd,F_SETFL,fl|O_NONBLOCK);
    int r=connect(fd,(struct sockaddr*)&d,sizeof d);
    if(r<0 && errno==EINPROGRESS){
        fd_set w; FD_ZERO(&w); FD_SET(fd,&w);
        struct timeval ct={0,800000};
        if(select(fd+1,NULL,&w,NULL,&ct)<=0){ close(fd); return 0; }
        int err=0; socklen_t el=sizeof err;
        if(getsockopt(fd,SOL_SOCKET,SO_ERROR,&err,&el)<0 || err){ close(fd); return 0; }
    } else if(r<0){ close(fd); return 0; }
    fcntl(fd,F_SETFL,fl);
    struct timeval tv={0,800000};
    setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);
    setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof tv);
    char req[256];
    int rl=snprintf(req,sizeof req,
        "GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: lanternet\r\nConnection: close\r\n\r\n",path,ip);
    if(send(fd,req,rl,0)<0){ close(fd); return 0; }
    int n=0;
    while(n<cap-1){
        int k=recv(fd,out+n,cap-1-n,0);
        if(k<=0) break;
        n+=k;
    }
    out[n]=0;
    close(fd);
    return n>0;
}

void ssdp_probe(void){
    int s=socket(AF_INET,SOCK_DGRAM,0);
    if(s<0) return;
    int on=1; setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&on,sizeof on);
    unsigned char ttl=2; setsockopt(s,IPPROTO_IP,IP_MULTICAST_TTL,&ttl,sizeof ttl);
    struct sockaddr_in d; memset(&d,0,sizeof d);
    d.sin_family=AF_INET; d.sin_port=htons(1900);
    inet_pton(AF_INET,"239.255.255.250",&d.sin_addr);
    const char *m=
        "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n";
    sendto(s,m,strlen(m),0,(struct sockaddr*)&d,sizeof d);
    sendto(s,m,strlen(m),0,(struct sockaddr*)&d,sizeof d);

    char locip[SSDP_MAX_LOC][32]; char locpath[SSDP_MAX_LOC][128]; int locport[SSDP_MAX_LOC]; int nl=0;
    unsigned long end=now_ms()+2000;
    while(now_ms()<end && nl<SSDP_MAX_LOC){
        struct timeval tv={0,200000};
        fd_set fds; FD_ZERO(&fds); FD_SET(s,&fds);
        if(select(s+1,&fds,NULL,NULL,&tv)<=0) continue;
        char b[2048]; struct sockaddr_in from; socklen_t fl=sizeof from;
        int n=recvfrom(s,b,sizeof b-1,0,(struct sockaddr*)&from,&fl);
        if(n<=0) continue;
        b[n]=0;
        const char *l=find_ci(b,"location:");
        if(!l) continue;
        l+=9;
        while(*l==' ') l++;
        const char *u=find_ci(l,"http://");
        if(!u) continue;
        u+=7;
        char ipp[32]; int k=0;
        while(u[k] && u[k]!=':' && u[k]!='/' && k<31){ ipp[k]=u[k]; k++; }
        ipp[k]=0;
        int pt=80;
        if(u[k]==':') pt=atoi(u+k+1);
        const char *p=strchr(u,'/');
        if(!ipp[0] || !p || pt<=0 || pt>65535) continue;
        int dup=0;
        for(int j=0;j<nl;j++) if(!strcmp(locip[j],ipp)){ dup=1; break; }
        if(dup) continue;
        snprintf(locip[nl],sizeof locip[nl],"%s",ipp);
        snprintf(locpath[nl],sizeof locpath[nl],"%s",p);
        char *cr=strpbrk(locpath[nl],"\r\n");      /* header line ends here */
        if(cr) *cr=0;
        locport[nl]=pt;
        nl++;
    }
    close(s);

    for(int i=0;i<nl;i++){
        char ip[32]; unsigned int a;
        memcpy(ip,locip[i],sizeof ip); ip[sizeof ip-1]=0;
        if(inet_pton(AF_INET,ip,&a)!=1) continue;
        int hi=find_host(a);
        if(hi<0 || g_hosts[hi].name[0]) continue;     /* only label known hosts */
        char body[8192], nm[128];
        if(!http_get(ip,locport[i],locpath[i],body,sizeof body)) continue;
        if(!xml_tag(body,"friendlyName",nm,sizeof nm)){
            if(!xml_tag(body,"modelName",nm,sizeof nm)) continue;
        }
        if(nm[0]) host_set_name(hi,nm,7);
    }
}
