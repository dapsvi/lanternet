/* net.c - interface/IP/gateway discovery and the raw socket */
#include "lanternet.h"

int iface_index(const char *name){ return if_nametoindex(name); }

void find_default_iface(char *out, size_t n, unsigned int *gw){
    FILE *f=fopen("/proc/net/route","r");
    if(!f){ snprintf(out,n,"wlan0"); *gw=0; return; }
    char line[256];
    while(fgets(line,sizeof line,f)){
        char iface[64]; unsigned int dest,gwv,flags;
        /* the header line fails the %x parses, so it is skipped here */
        if(sscanf(line,"%63s %x %x %x",iface,&dest,&gwv,&flags)<4) continue;
        if(dest==0){ snprintf(out,n,"%s",iface); *gw=gwv; fclose(f); return; }
    }
    fclose(f);
    snprintf(out,n,"wlan0"); *gw=0;
}

/* first IPv4 address after a "via " token in a command's output */
static unsigned int gw_from_cmd(const char *cmd){
    FILE *p=popen(cmd,"r");
    if(!p) return 0;
    char line[512]; unsigned int gw=0;
    while(fgets(line,sizeof line,p)){
        char *via=strstr(line,"via ");
        if(!via) continue;
        char tok[64]; int i=0; via+=4;
        while(via[i] && via[i]!=' ' && via[i]!='\t' && via[i]!='\n' && i<63){ tok[i]=via[i]; i++; }
        tok[i]=0;
        struct in_addr a;
        if(inet_pton(AF_INET,tok,&a)==1){ gw=a.s_addr; break; }
    }
    pclose(p);
    return gw;
}

/* Android hides the default route from /proc/net/route and keeps the real one
   in a per-network table, so "ip route show default" often comes back empty.
   Ask the kernel which route it would actually use, then widen the search. */
unsigned int gw_via_ip_cmd(void){
    unsigned int gw = gw_from_cmd("ip -4 route get 8.8.8.8 2>/dev/null");
    if(!gw) gw = gw_from_cmd("ip -4 route show table all 2>/dev/null | grep -w default");
    if(!gw) gw = gw_from_cmd("ip -4 route show default 2>/dev/null");
    return gw;
}

void get_iface_info(const char *iface){
    /* our MAC straight off the packet socket */
    struct sockaddr_ll sll; socklen_t sl=sizeof sll; memset(&sll,0,sizeof sll);
    if(g_sock>=0 && getsockname(g_sock,(struct sockaddr*)&sll,&sl)==0 && sll.sll_halen==6)
        memcpy(g_mymac, sll.sll_addr, 6);
    if(!(g_mymac[0]||g_mymac[1])){
        char p[128], line[64];
        snprintf(p,sizeof p,"/sys/class/net/%s/address",iface);
        FILE *f=fopen(p,"r");
        if(f){ if(fgets(line,sizeof line,f)) parse_mac(line,g_mymac); fclose(f); }
    }
    struct ifaddrs *ifa=NULL,*it;
    if(getifaddrs(&ifa)==0){
        for(it=ifa;it;it=it->ifa_next){
            if(!it->ifa_addr||it->ifa_addr->sa_family!=AF_INET) continue;
            if(strcmp(it->ifa_name,iface)) continue;
            g_myip = ((struct sockaddr_in*)it->ifa_addr)->sin_addr.s_addr;
            if(it->ifa_netmask) g_mask = ((struct sockaddr_in*)it->ifa_netmask)->sin_addr.s_addr;
        }
        freeifaddrs(ifa);
    }
    if(g_mask==0) g_mask = htonl(0xffffff00);
    if(g_myip==0){   /* netlink can be blocked; ask the kernel which source it would use */
        int u=socket(AF_INET,SOCK_DGRAM,0);
        struct sockaddr_in t; memset(&t,0,sizeof t);
        t.sin_family=AF_INET; t.sin_port=htons(53); inet_pton(AF_INET,"8.8.8.8",&t.sin_addr);
        if(connect(u,(struct sockaddr*)&t,sizeof t)==0){
            struct sockaddr_in l; socklen_t ll=sizeof l;
            if(getsockname(u,(struct sockaddr*)&l,&ll)==0) g_myip=l.sin_addr.s_addr;
        }
        close(u);
    }
    if(g_gwip==0) g_gwip = gw_via_ip_cmd();
    if(g_gwip==0) g_gwip = (g_myip & g_mask) | htonl(1);
}

int open_raw(void){
    int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if(s<0) return -1;
    int rb = 4*1024*1024;   /* hundreds of ARP replies must fit, or they drop */
    setsockopt(s, SOL_SOCKET, SO_RCVBUFFORCE, &rb, sizeof rb);
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, &rb, sizeof rb);
    int sb = 1*1024*1024;   /* a full TX ring must never wedge the loop */
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, &sb, sizeof sb);
    struct timeval tv; tv.tv_sec=0; tv.tv_usec=80000;   /* and never block */
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    int fl=fcntl(s,F_GETFL,0); fcntl(s,F_SETFL,fl|O_NONBLOCK);
    struct sockaddr_ll sll; memset(&sll,0,sizeof sll);
    sll.sll_family=AF_PACKET; sll.sll_protocol=htons(ETH_P_ARP); sll.sll_ifindex=g_ifidx;
    if(bind(s,(struct sockaddr*)&sll,sizeof sll)<0){ close(s); return -1; }
    return s;
}

/* Do we currently have an IPv4 address on the default route? */
int have_link(void){
    int u=socket(AF_INET,SOCK_DGRAM,0);
    if(u<0) return 0;
    struct sockaddr_in t; memset(&t,0,sizeof t);
    t.sin_family=AF_INET; t.sin_port=htons(53); inet_pton(AF_INET,"8.8.8.8",&t.sin_addr);
    unsigned int ip=0;
    if(connect(u,(struct sockaddr*)&t,sizeof t)==0){
        struct sockaddr_in l; socklen_t ll=sizeof l;
        if(getsockname(u,(struct sockaddr*)&l,&ll)==0) ip=l.sin_addr.s_addr;
    }
    close(u);
    return ip!=0;
}

/* Re-detect interface/IP/gateway and reopen the raw socket. 0 = ok. */
int setup_network(void){
    char iface[64]; unsigned int gw=0;
    unsigned int explicit_gw = g_gwip;   /* keep --gw across re-detection */
    find_default_iface(iface,sizeof iface,&gw);
    snprintf(g_ifname,sizeof g_ifname,"%s",iface);
    g_ifidx = iface_index(iface);
    if(g_ifidx<=0) return -1;
    if(g_sock>=0){ close(g_sock); g_sock=-1; }
    g_sock = open_raw();
    if(g_sock<0) return -1;
    g_gwip=gw; g_gwmac[0]=g_gwmac[1]=0; g_nhost=0; g_v6_ok=0; g_myip=0; g_mask=0;
    get_iface_info(iface);
    if(explicit_gw) g_gwip = explicit_gw;
    return 0;
}
