/* dhcp.c - DHCP: passive hostname/vendor sniffing and local lease files */
#include "lanternet.h"

static void lease_add(const char *ips,const char *macs,const char *nm){
    unsigned int a; unsigned char mac[6];
    if(inet_pton(AF_INET,ips,&a)!=1) return;
    if(!parse_mac(macs,mac)) return;
    add_host(a,mac);
    if(nm && nm[0]){ int hi=find_host(a); if(hi>=0 && !g_hosts[hi].name[0]) host_set_name(hi,nm,5); }
}

void merge_dhcp_leases(void){
    /* dnsmasq: <expiry> <mac> <ip> <hostname> <client-id> */
    FILE *f=fopen("/data/misc/dhcp/dnsmasq.leases","r");
    if(f){
        char line[512];
        while(fgets(line,sizeof line,f)){
            unsigned long exp; char macs[32]="", ips[64]="", nm[128]="";
            if(sscanf(line,"%lu %31s %63s %127s",&exp,macs,ips,nm)<4) continue;
            if(!strcmp(nm,"*")) nm[0]=0;
            lease_add(ips,macs,nm);
        }
        fclose(f);
    }
    /* ISC dhcpd: lease <ip> { ... hardware ethernet <mac>; client-hostname "<n>"; ... } */
    f=fopen("/data/misc/dhcp/dhcpd.leases","r");
    if(f){
        char line[512], ips[64]="", macs[32]="", nm[128]="";
        int in=0;
        while(fgets(line,sizeof line,f)){
            char *p;
            if((p=strstr(line,"lease "))){
                if(in) lease_add(ips,macs,nm);
                in=1; ips[0]=macs[0]=nm[0]=0;
                if(sscanf(p+6,"%63s",ips)==1){ char *b=strchr(ips,'{'); if(b) *b=0; }
            } else if((p=strstr(line,"hardware ethernet "))){
                if(sscanf(p+18,"%31s",macs)==1){ char *s=strchr(macs,';'); if(s) *s=0; }
            } else if((p=strstr(line,"client-hostname "))){
                char *q=strchr(p,'"');
                if(q) sscanf(q+1,"%127[^\"]",nm);
            } else if(strchr(line,'}') && in){
                lease_add(ips,macs,nm); in=0; ips[0]=macs[0]=nm[0]=0;
            }
        }
        if(in) lease_add(ips,macs,nm);
        fclose(f);
    }
}

static int dhcp_open(void){
    int s=socket(AF_PACKET,SOCK_RAW,htons(0x0800));
    if(s<0) return -1;
    struct sockaddr_ll sll; memset(&sll,0,sizeof sll);
    sll.sll_family=AF_PACKET; sll.sll_protocol=htons(0x0800); sll.sll_ifindex=g_ifidx;
    if(bind(s,(struct sockaddr*)&sll,sizeof sll)<0){ close(s); return -1; }
    return s;
}

/* take the option-12/60 strings from a DHCP message if the host has none yet */
static void apply_dhcp(int i,const char *name,const char *vendor){
    if(name[0] && !g_hosts[i].name[0]) host_set_name(i,name,8);
    if(vendor[0] && !g_hosts[i].vendor[0])
        snprintf(g_hosts[i].vendor,sizeof g_hosts[i].vendor,"%.*s",
                 (int)sizeof g_hosts[i].vendor-1,vendor);
}

static void dhcp_ingest(const unsigned char *p,int n){
    if(n<42) return;
    int off=14;                                       /* AF_PACKET gives us Ethernet */
    if(p[12]==0x81&&p[13]==0x00) off=18;              /* single 802.1Q tag */
    else if(p[12]!=0x08||p[13]!=0x00) return;         /* IPv4 only */
    const unsigned char *ip=p+off;
    int ihl=(ip[0]&0x0f)*4;
    if(ihl<20 || ip[9]!=17) return;                   /* UDP only */
    if(n<off+ihl+8) return;
    const unsigned char *udp=ip+ihl;
    unsigned int sp=(udp[0]<<8)|udp[1], dp=(udp[2]<<8)|udp[3];
    if(!((sp==68&&dp==67)||(sp==67&&dp==68))) return;
    const unsigned char *b=udp+8;
    int bl=n-off-ihl-8;
    if(bl<240) return;
    if(!(b[236]==0x63&&b[237]==0x82&&b[238]==0x53&&b[239]==0x63)) return;
    const unsigned char *ch=b+28;                  /* client MAC */
    unsigned int yiaddr; memcpy(&yiaddr,b+16,4);
    unsigned int ciaddr; memcpy(&ciaddr,b+12,4);

    if(b[0]==2){                                   /* BOOTREPLY: assign IP to that MAC */
        if(yiaddr) add_host(yiaddr,ch);
        return;
    }
    if(b[0]!=1) return;                            /* BOOTREQUEST */
    char name[128]="", vendor[128]="";
    int o=240;
    while(o<bl){
        int c=b[o++];
        if(c==255) break;
        if(c==0) continue;
        if(o>=bl) break;
        int L=b[o++];
        if(o+L>bl) break;
        if(c==DHCP_OPT_HOSTNAME && L<127)      snprintf(name,sizeof name,"%.*s",L,(const char*)b+o);
        else if(c==DHCP_OPT_VENDOR && L<127)   snprintf(vendor,sizeof vendor,"%.*s",L,(const char*)b+o);
        o+=L;
    }
    for(char *q=name;*q;q++)   if((unsigned char)*q<0x20 || (unsigned char)*q>0x7e) *q='_';
    for(char *q=vendor;*q;q++) if((unsigned char)*q<0x20 || (unsigned char)*q>0x7e) *q='_';
    if(ciaddr){                                    /* renew/rebind: we know its IP */
        add_host(ciaddr,ch);
        int hi=find_host(ciaddr);
        if(hi>=0){ apply_dhcp(hi,name,vendor); return; }
    }
    for(int i=0;i<g_nhost;i++) if(!memcmp(g_hosts[i].mac,ch,6)){   /* DISCOVER: match by MAC */
        apply_dhcp(i,name,vendor);
        break;
    }
}

void dhcp_listen(int ms){
    int s=dhcp_open();
    if(s<0) return;
    unsigned long end=now_ms()+(unsigned long)ms;
    while(now_ms()<end){
        struct timeval tv={0,200000};
        fd_set fds; FD_ZERO(&fds); FD_SET(s,&fds);
        if(select(s+1,&fds,NULL,NULL,&tv)<=0) continue;
        unsigned char b[2048];
        int n=recv(s,b,sizeof b,0);
        if(n>0) dhcp_ingest(b,n);
    }
    close(s);
}
