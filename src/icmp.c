/* icmp.c - ICMP echo (TTL/OS hint) and ICMPv6 echo (IPv6 presence) */
#include "lanternet.h"

int icmp_open(void){
    int s=socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
    if(s<0) return -1;
    int rb=4*1024*1024;
    setsockopt(s,SOL_SOCKET,SO_RCVBUFFORCE,&rb,sizeof rb);
    setsockopt(s,SOL_SOCKET,SO_RCVBUF,&rb,sizeof rb);
    int on=1; setsockopt(s,IPPROTO_IP,IP_RECVTTL,&on,sizeof on);
    return s;
}

void icmp_echo(int s,unsigned int ip,unsigned short id){
    unsigned char b[24]; memset(b,0,sizeof b);
    b[0]=8;
    b[4]=id>>8; b[5]=id&0xff; b[6]=0; b[7]=1;
    for(int i=8;i<24;i++) b[i]=(unsigned char)(i*7);
    unsigned short c=inet_csum(b,24);
    b[2]=c>>8; b[3]=c&0xff;
    struct sockaddr_in d; memset(&d,0,sizeof d);
    d.sin_family=AF_INET; d.sin_addr.s_addr=ip;
    if(g_dry) return;
    sendto(s,b,24,0,(struct sockaddr*)&d,sizeof d);
}

void icmp_handle(int s){
    unsigned char buf[1024];
    struct iovec iov={buf,sizeof buf};
    unsigned char cbuf[256];
    struct msghdr mh; memset(&mh,0,sizeof mh);
    struct sockaddr_in from; memset(&from,0,sizeof from);
    mh.msg_name=&from; mh.msg_namelen=sizeof from;
    mh.msg_iov=&iov; mh.msg_iovlen=1;
    mh.msg_control=cbuf; mh.msg_controllen=sizeof cbuf;
    int n=recvmsg(s,&mh,0);
    if(n<28) return;
    int ihl=(buf[0]&0x0f)*4;
    if(buf[ihl]!=0) return;                 /* want echo reply */
    int ttl=0;
    for(struct cmsghdr *c=CMSG_FIRSTHDR(&mh); c; c=CMSG_NXTHDR(&mh,c))
        if(c->cmsg_level==IPPROTO_IP && c->cmsg_type==IP_TTL) ttl=*(int*)CMSG_DATA(c);
    int hi=find_host(from.sin_addr.s_addr);
    if(hi<0) return;
    if(ttl>0) g_hosts[hi].ttl=ttl;
    host_seen(from.sin_addr.s_addr);
}

int icmp6_open(void){
    return socket(AF_INET6,SOCK_RAW,IPPROTO_ICMPV6);
}

void icmp6_echo(int s,const unsigned char *dst_ll,unsigned short id){
    unsigned char msg[24]; memset(msg,0,sizeof msg);
    msg[0]=128;                             /* echo request */
    msg[4]=id>>8; msg[5]=id&0xff; msg[6]=0; msg[7]=1;
    for(int i=8;i<24;i++) msg[i]=(unsigned char)(i*11);
    unsigned char src_ll[16]; eui64_ll(g_mymac,src_ll);
    unsigned short c=icmp6_csum(src_ll,(const unsigned char*)dst_ll,msg,24);
    msg[2]=c>>8; msg[3]=c&0xff;
    struct sockaddr_in6 d; memset(&d,0,sizeof d);
    d.sin6_family=AF_INET6; d.sin6_scope_id=g_ifidx;
    memcpy(&d.sin6_addr,dst_ll,16);
    if(g_dry) return;
    sendto(s,msg,24,0,(struct sockaddr*)&d,sizeof d);
}

static void mac_from_ll(const unsigned char *ll,unsigned char *mac){
    mac[0]=ll[8]^0x02; mac[1]=ll[9]; mac[2]=ll[10];
    mac[3]=ll[13];     mac[4]=ll[14]; mac[5]=ll[15];
}

void icmp6_handle(int s){
    unsigned char buf[1024];
    struct sockaddr_in6 from; socklen_t fl=sizeof from;
    int n=recvfrom(s,buf,sizeof buf,0,(struct sockaddr*)&from,&fl);
    if(n<8 || buf[0]!=129) return;           /* want echo reply */
    unsigned char mac[6]; mac_from_ll((unsigned char*)&from.sin6_addr,mac);
    for(int i=0;i<g_nhost;i++)
        if(!memcmp(g_hosts[i].mac,mac,6)) g_hosts[i].v6=1;
}
