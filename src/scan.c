/* scan.c - the host table, the ARP sweep, and gateway resolution */
#include "lanternet.h"

void add_host(unsigned int ip, const unsigned char *mac){
    static const unsigned char none[6]={0,0,0,0,0,0};
    static const unsigned char all6[6]={0xff,0xff,0xff,0xff,0xff,0xff};
    /* /proc/net/arp keeps unresolved rows with a zero hardware address */
    if(!mac || !memcmp(mac,none,6) || !memcmp(mac,all6,6)) return;
    if(ip==g_myip) return;
    for(int i=0;i<g_nhost;i++) if(g_hosts[i].ip==ip){ memcpy(g_hosts[i].mac,mac,6); return; }
    if(g_nhost>=MAXHOST) return;
    memset(&g_hosts[g_nhost],0,sizeof g_hosts[0]);
    g_hosts[g_nhost].ip=ip;
    memcpy(g_hosts[g_nhost].mac,mac,6);
    g_nhost++;
}

int find_host(unsigned int ip){
    for(int i=0;i<g_nhost;i++) if(g_hosts[i].ip==ip) return i;
    return -1;
}

void host_set_name(int idx, const char *nm, int src){
    if(idx<0 || !nm || !nm[0]) return;
    if(src!=SRC_USER && name_is_junk(nm)) return;
    size_t L=strlen(nm);
    if(L>sizeof g_hosts[idx].name - 1) L=sizeof g_hosts[idx].name - 1;
    memcpy(g_hosts[idx].name, nm, L);
    g_hosts[idx].name[L]=0;
    g_hosts[idx].name_src=src;
}

int recv_arp(int ms){
    unsigned char buf[2048];
    struct timeval tv; tv.tv_sec=0; tv.tv_usec=ms*1000;
    fd_set fds; FD_ZERO(&fds); FD_SET(g_sock,&fds);
    if(select(g_sock+1,&fds,NULL,NULL,&tv)<=0) return 0;
    int n=recv(g_sock,buf,sizeof buf,0);
    if(n<42) return 0;
    if(buf[12]!=0x08||buf[13]!=0x06) return 0;
    const struct arp_hdr *a=(const struct arp_hdr*)(buf+14);
    if(ntohs(a->op)==2){
        add_host(a->spa,a->sha);
        if(!(g_gwmac[0]||g_gwmac[1]) || a->spa==g_gwip || memcmp(a->sha,g_gwmac,6)) host_seen(a->spa);
        return 1;
    }
    return 0;
}

void host_seen(unsigned int ip){
    int i=find_host(ip);
    if(i>=0) g_hosts[i].seen_ms=now_ms();
}

static void neigh_stream(FILE *f){
    char line[512];
    while(fgets(line,sizeof line,f)){
        char ip[64]="", macs[32]="";
        if(sscanf(line,"%63s",ip)!=1) continue;
        char *l=strstr(line,"lladdr ");
        if(l) sscanf(l+7,"%31s",macs);
        if(!macs[0] || strstr(line,"FAILED") || strstr(line,"INCOMPLETE")) continue;
        unsigned char mac[6];
        if(!parse_mac(macs,mac)) continue;
        unsigned int a;
        if(inet_pton(AF_INET,ip,&a)==1){
            add_host(a,mac);
        } else if(strchr(ip,':')){                 /* IPv6 neighbour */
            for(int i=0;i<g_nhost;i++) if(!memcmp(g_hosts[i].mac,mac,6)){
                /* prefer a routable address over a link-local one */
                if(!g_hosts[i].ip6[0] ||
                   (!strncmp(g_hosts[i].ip6,"fe80",4) && strncmp(ip,"fe80",4)))
                    snprintf(g_hosts[i].ip6,sizeof g_hosts[i].ip6,"%s",ip);
                g_hosts[i].v6=1;
                break;
            }
        }
    }
}

void merge_neigh(void){
    FILE *f=popen("ip neigh show 2>/dev/null","r");
    if(f){ neigh_stream(f); pclose(f); }
    FILE *g=popen("ip -6 neigh show 2>/dev/null","r");
    if(g){ neigh_stream(g); pclose(g); }
}

/* one "<ip> <type> <flags> <mac>" row of /proc/net/arp */
static int arp_line(const char *line, unsigned int *ip, unsigned char *mac){
    char ips[32], hws[32]; unsigned type, flags;
    if(sscanf(line,"%31s %x %x %31s",ips,&type,&flags,hws)<4) return 0;
    if(inet_pton(AF_INET,ips,ip)!=1) return 0;
    return parse_mac(hws,mac);
}

int arp_from_file(unsigned int ip, unsigned char *out){
    FILE *f=fopen("/proc/net/arp","r");
    if(!f) return 0;
    char line[256]; int first=1, ok=0;
    while(fgets(line,sizeof line,f)){
        if(first){ first=0; continue; }
        unsigned int a; unsigned char mac[6];
        if(arp_line(line,&a,mac) && a==ip){ memcpy(out,mac,6); ok=1; break; }
    }
    fclose(f);
    return ok;
}

int arp_probe(unsigned int ip, unsigned char *out){
    static const unsigned char bcast[6]={0xff,0xff,0xff,0xff,0xff,0xff};
    static const unsigned char zero[6]={0,0,0,0,0,0};
    for(int t=0;t<5;t++){
        send_arp(1,bcast,g_myip,g_mymac,ip,zero);
        for(int k=0;k<3;k++){
            struct timeval tv; tv.tv_sec=0; tv.tv_usec=100000;
            fd_set fds; FD_ZERO(&fds); FD_SET(g_sock,&fds);
            if(select(g_sock+1,&fds,NULL,NULL,&tv)<=0) continue;
            unsigned char buf[2048]; int n=recv(g_sock,buf,sizeof buf,0);
            if(n>=42 && buf[12]==0x08 && buf[13]==0x06){
                const struct arp_hdr *a=(const struct arp_hdr*)(buf+14);
                if(ntohs(a->op)==2 && a->spa==ip){ memcpy(out,a->sha,6); return 1; }
            }
        }
    }
    return 0;
}

int resolve_ip(unsigned int ip, unsigned char *out){
    int i=find_host(ip);
    if(i>=0){ memcpy(out,g_hosts[i].mac,6); return 1; }
    if(arp_from_file(ip,out)){ add_host(ip,out); return 1; }
    if(arp_probe(ip,out)){ add_host(ip,out); return 1; }
    return 0;
}

void load_gwmac(void){
    for(int i=0;i<g_nhost;i++) if(g_hosts[i].ip==g_gwip){ memcpy(g_gwmac,g_hosts[i].mac,6); break; }
    if(g_gwmac[0]||g_gwmac[1]) return;
    if(arp_from_file(g_gwip,g_gwmac)) return;
    static const unsigned char bcast[6]={0xff,0xff,0xff,0xff,0xff,0xff};
    static const unsigned char zero[6]={0,0,0,0,0,0};
    for(int t=0;t<10;t++){
        send_arp(1,bcast,g_myip,g_mymac,g_gwip,zero);
        struct timeval tv; tv.tv_sec=0; tv.tv_usec=200000;
        fd_set fds; FD_ZERO(&fds); FD_SET(g_sock,&fds);
        if(select(g_sock+1,&fds,NULL,NULL,&tv)>0){
            unsigned char buf[2048]; int n=recv(g_sock,buf,sizeof buf,0);
            if(n>=42 && buf[12]==0x08 && buf[13]==0x06){
                const struct arp_hdr *a=(const struct arp_hdr*)(buf+14);
                if(ntohs(a->op)==2 && a->spa==g_gwip){ memcpy(g_gwmac,a->sha,6); break; }
            }
        }
    }
}

/* One sweep of the subnet plus the local tables. Fills g_hosts, no name work. */
void arp_sweep(void){
    struct in_addr n,m; char ns[32],ms[32];
    n.s_addr = g_myip & g_mask;
    m.s_addr = g_mask;
    inet_ntop(AF_INET,&n,ns,sizeof ns);
    inet_ntop(AF_INET,&m,ms,sizeof ms);
    unsigned int bcast = g_myip | ~g_mask;
    unsigned int first = ntohl(n.s_addr) + 1;
    unsigned int last  = ntohl(bcast) - 1;
    if(last < first) last = first;
    unsigned long total = (unsigned long)last - (unsigned long)first + 1;
    unsigned long cnt = total;
    if(!g_json && !g_sweep_quiet)
        printf("subnet %s/%s (%lu hosts)\n", ns, ms, cnt);

    static const unsigned char bcastmac[6]={0xff,0xff,0xff,0xff,0xff,0xff};
    static const unsigned char zero6[6]={0,0,0,0,0,0};
    for(unsigned long i=0;i<cnt;i++){
        unsigned int tip = htonl(first + (unsigned int)i);
        if(tip == g_myip) continue;
        send_arp(1,bcastmac,g_myip,g_mymac,tip,zero6);
        if((i & (SWEEP_BATCH-1)) == (SWEEP_BATCH-1))
            for(int k=0;k<10000 && recv_arp(0);k++);
        if((i & (SWEEP_PAUSE_EVERY-1)) == (SWEEP_PAUSE_EVERY-1)) usleep(SWEEP_PAUSE_US);
    }
    /* Wait for replies only until the wire goes quiet */
    unsigned long tail = SWEEP_TAIL_MAX_MS + cnt/64;
    if(tail > 15000) tail = 15000;
    unsigned long deadline = now_ms() + tail;
    unsigned long lastrx = now_ms();
    while(now_ms() < deadline && (now_ms() - lastrx) < SWEEP_QUIET_MS){
        if(recv_arp(50)) lastrx = now_ms();
    }

    /* merge the kernel ARP table */
    FILE *af=fopen("/proc/net/arp","r");
    if(af){
        char line[256]; int firstl=1;
        while(fgets(line,sizeof line,af)){
            if(firstl){ firstl=0; continue; }
            unsigned int a; unsigned char mac[6];
            if(arp_line(line,&a,mac)) add_host(a,mac);
        }
        fclose(af);
    }

    /* kernel neighbour table (v4+v6) + any local DHCP leases */
    merge_neigh();
    merge_dhcp_leases();


    /* the gateway is a target too, even when it sits outside the swept range */
    if(g_gwip && find_host(g_gwip)<0){ unsigned char gm[6]; resolve_ip(g_gwip,gm); }
}



