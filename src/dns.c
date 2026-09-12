/* dns.c - DNS name helpers, LAN resolver discovery, batched PTR lookups */
#include "lanternet.h"

int dns_skip_name(const unsigned char *p,int n,int off){
    while(off<n){
        unsigned len=p[off];
        if((len&0xc0)==0xc0) return off+2;
        if(len==0) return off+1;
        off += 1+len;
    }
    return -1;
}

int dns_read_name(const unsigned char *p,int n,int off,char *out,int osz){
    int o=0, guard=0;
    while(off<n && guard++<64){
        unsigned len=p[off];
        if((len&0xc0)==0xc0){ if(off+1>=n) break; off=((len&0x3f)<<8)|p[off+1]; continue; }
        if(len==0){ off++; break; }
        if(off+1+(int)len>n) break;
        if(o && o<osz-1) out[o++]='.';
        for(int i=0;i<(int)len && o<osz-1;i++){
            unsigned char c=p[off+1+i];
            out[o++] = (char)c;
        }
        off += 1+len;
    }
    if(o<osz) out[o]=0;
    return off;
}

int dns_enc_name(unsigned char *b,int max,const char *name){
    int o=0; const char *p=name;
    while(*p){
        const char *dot=strchr(p,'.');
        int L=dot?(int)(dot-p):(int)strlen(p);
        if(L<=0||L>63||o+1+L>=max) return -1;
        b[o++]=(unsigned char)L;
        memcpy(b+o,p,L); o+=L;
        if(!dot) break;
        p=dot+1;
    }
    b[o++]=0;
    return o;
}

unsigned int dns_server_addr(void){
    FILE *f=fopen("/proc/net/pnp","r");
    if(f){
        char line[256], ips[64];
        while(fgets(line,sizeof line,f))
            if(sscanf(line,"nameserver %63s",ips)==1){
                unsigned int a;
                if(inet_pton(AF_INET,ips,&a)==1){ fclose(f); return a; }
            }
        fclose(f);
    }
    FILE *p=popen("getprop net.dns1 2>/dev/null","r");
    if(p){
        char line[64]="";
        if(fgets(line,sizeof line,p)){
            line[strcspn(line,"\n")]=0;
            unsigned int a;
            if(inet_pton(AF_INET,line,&a)==1){ pclose(p); return a; }
        }
        pclose(p);
    }
    return g_gwip;
}

void dns_batch_ptr(int ms){
    unsigned int srv = dns_server_addr();
    if(!srv) return;
    int s=socket(AF_INET,SOCK_DGRAM,0);
    if(s<0) return;
    struct sockaddr_in d; memset(&d,0,sizeof d);
    d.sin_family=AF_INET; d.sin_port=htons(53); d.sin_addr.s_addr=srv;
    unsigned char q[160];
    int sent=0;
    for(int i=0;i<g_nhost;i++){
        if(g_hosts[i].name[0]) continue;
        unsigned int h=ntohl(g_hosts[i].ip);
        char rev[64];
        snprintf(rev,sizeof rev,"%u.%u.%u.%u.in-addr.arpa",
            h&0xff,(h>>8)&0xff,(h>>16)&0xff,(h>>24)&0xff);
        memset(q,0,sizeof q);
        unsigned short id=(unsigned short)(i+1);
        q[0]=id>>8; q[1]=id&0xff; q[5]=1;    /* RD */
        int o=dns_enc_name(q+12,sizeof q-16,rev);
        if(o<0) continue;
        int qn=12+o;
        q[qn++]=0; q[qn++]=12; q[qn++]=0; q[qn++]=1;   /* PTR IN */
        sendto(s,q,qn,0,(struct sockaddr*)&d,sizeof d);
        sent++;
    }
    if(!sent){ close(s); return; }
    unsigned long end=now_ms()+(unsigned long)ms;
    while(now_ms()<end){
        struct timeval tv={0,150000};
        fd_set fds; FD_ZERO(&fds); FD_SET(s,&fds);
        if(select(s+1,&fds,NULL,NULL,&tv)<=0) continue;
        unsigned char b[1024];
        int n=recv(s,b,sizeof b,0);
        if(n<12) continue;
        int id=(b[0]<<8)|b[1];
        if(id<1 || id>g_nhost) continue;
        int idx=id-1;
        int qd=(b[4]<<8)|b[5], an=(b[6]<<8)|b[7];
        if(an<1) continue;
        int off=12;
        for(int k=0;k<qd;k++){ off=dns_skip_name(b,n,off); if(off<0) break; off+=4; }
        if(off<0) continue;
        for(int k=0;k<an && off+10<=n;k++){
            char owner[128];
            off=dns_read_name(b,n,off,owner,sizeof owner);
            if(off<0||off+10>n) break;
            int type=(b[off]<<8)|b[off+1];
            off+=8;
            int rdl=(b[off]<<8)|b[off+1]; off+=2;
            if(off+rdl>n) break;
            if(type==12){
                char tgt[128]="";
                dns_read_name(b,n,off,tgt,sizeof tgt);
                char *dot=strstr(tgt,".local");
                if(dot) *dot=0;
                if(tgt[0] && !g_hosts[idx].name[0]) host_set_name(idx,tgt,4);
                break;
            }
            off+=rdl;
        }
    }
    close(s);
}
