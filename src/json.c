/* json.c - human and machine readable host listings */
#include "lanternet.h"

static void jesc(const char *s, char *out, int n){
    int o=0;
    for(int i=0; s[i] && o<n-2; i++){
        unsigned char c=s[i];
        if(c=='"'||c=='\\'){ out[o++]='\\'; out[o++]=(char)c; }
        else if(c<0x20) out[o++]=' ';
        else out[o++]=(char)c;
    }
    out[o]=0;
}

static void clean(char *s){
    for(char *q=s;*q;q++) if((unsigned char)*q<0x20) *q=' ';
}

const char *name_source(int s){
    switch(s){
        case SRC_USER: return "user";
        case SRC_NBNS: return "nbns";
        case SRC_MDNS: return "mdns";
        case SRC_DNS: return "dns";
        case SRC_LEASE: return "lease";
        case SRC_MDNSVC: return "mdns-svc";
        case SRC_SSDP: return "ssdp";
        case SRC_DHCP: return "dhcp";
        case SRC_CACHE: return "cache";
        default: return "-";
    }
}

static int term_width(void){
    struct winsize ws;
    if(ioctl(STDOUT_FILENO,TIOCGWINSZ,&ws)==0 && ws.ws_col>=CONSOLE_MIN)
        return ws.ws_col>CONSOLE_MAX?CONSOLE_MAX:(int)ws.ws_col;
    const char *c=getenv("COLUMNS");
    if(c){ int v=atoi(c); if(v>=CONSOLE_MIN) return v>CONSOLE_MAX?CONSOLE_MAX:v; }
    return CONSOLE_DEFAULT;
}

#define LBLW 8                       /* label column width: "  Name    : " */

/* one labelled field; the value wraps to the console width with the
   continuation lines aligned under the value column */
static void field(const char *label,const char *val,int width){
    if(!val||!val[0]) return;
    char pre[32];
    snprintf(pre,sizeof pre,"  %-*s: ",LBLW,label);
    int pl=(int)strlen(pre);
    int avail=width-pl; if(avail<16) avail=16;
    const char *p=val;
    int first=1;
    while(*p){
        if(first){ fputs(pre,stdout); first=0; }
        else printf("%*s",pl,"");
        int n=(int)strlen(p), take=avail;
        if(n<=take){ fputs(p,stdout); putchar('\n'); break; }
        int br=take;
        while(br>0 && p[br]!=' ') br--;
        if(br<=0) br=take;
        fwrite(p,1,(size_t)br,stdout); putchar('\n');
        p+=br;
        while(*p==' ') p++;
    }
}

void print_hosts(void){
    char gws[32]; struct in_addr g; g.s_addr=g_gwip; inet_ntop(AF_INET,&g,gws,sizeof gws);
    if(g_json){
        unsigned int dns=dns_server_addr(); char dnss[32]; struct in_addr da; da.s_addr=dns;
        inet_ntop(AF_INET,&da,dnss,sizeof dnss);
        char self[160]=""; self_device_name(self,sizeof self);
        char mymac[20]; mac_str(g_mymac,mymac);
        char myip[32]; struct in_addr sa; sa.s_addr=g_myip; inet_ntop(AF_INET,&sa,myip,sizeof myip);
        char se[360]; jesc(self,se,sizeof se);
        printf("{\"interface\":\"%s\",\"gateway\":\"%s\",\"dns\":\"%s\","
               "\"self\":{\"ip\":\"%s\",\"mac\":\"%s\",\"name\":\"%s\"},\"hosts\":[",
               g_ifname, gws, dnss, myip, mymac, se);
        for(int i=0;i<g_nhost;i++){
            char ip[32], mac[20], ven[80], nm[160], v6[64];
            struct in_addr a; a.s_addr=g_hosts[i].ip; inet_ntop(AF_INET,&a,ip,sizeof ip);
            mac_str(g_hosts[i].mac,mac);
            jesc(g_hosts[i].vendor,ven,sizeof ven);
            jesc(g_hosts[i].name,nm,sizeof nm);
            jesc(g_hosts[i].ip6,v6,sizeof v6);
            printf("%s{\"ip\":\"%s\",\"mac\":\"%s\",\"vendor\":\"%s\",\"name\":\"%s\","
                   "\"name_src\":\"%s\",\"os\":\"%s\",\"ttl\":%d,\"ipv6\":%s,\"ip6\":\"%s\","
                   "\"gateway\":%s,\"random_mac\":%s,\"cut\":%s}",
                i?",":"", ip, mac, ven, nm,
                name_source(g_hosts[i].name_src),
                ttl_hint(g_hosts[i].ttl), g_hosts[i].ttl,
                g_hosts[i].v6?"true":"false", v6,
                (g_hosts[i].ip==g_gwip)?"true":"false",
                (g_hosts[i].mac[0]&0x02)?"true":"false",
                g_hosts[i].cut?"true":"false");
        }
        printf("]}\n");
        return;
    }
    int width=term_width();
    printf("\n");
    for(int i=0;i<g_nhost;i++){
        char ip[32], mac[20];
        struct in_addr a; a.s_addr=g_hosts[i].ip; inet_ntop(AF_INET,&a,ip,sizeof ip);
        mac_str(g_hosts[i].mac,mac);
        if(i) printf("\n");                  /* blank line separates the entries */
        printf("%-15s %s\n", ip, mac);
        if(g_hosts[i].name[0]){
            char nm[160];
            snprintf(nm,sizeof nm,"%s (%s)", g_hosts[i].name, name_source(g_hosts[i].name_src));
            clean(nm); field("Name", nm, width);
        }
        if(g_hosts[i].vendor[0]){
            char vn[96]; snprintf(vn,sizeof vn,"%s",g_hosts[i].vendor); clean(vn);
            field("Vendor", vn, width);
        }
        if(g_hosts[i].ttl) field("OS", ttl_hint(g_hosts[i].ttl), width);
        if(g_hosts[i].ip6[0]) field("IPv6", g_hosts[i].ip6, width);
        char flags[96]="";
        if(g_hosts[i].ip==g_gwip) snprintf(flags+strlen(flags),sizeof flags-strlen(flags),"gateway ");
        if(g_hosts[i].cut)        snprintf(flags+strlen(flags),sizeof flags-strlen(flags),"cut ");
        if(g_hosts[i].mac[0]&0x02) snprintf(flags+strlen(flags),sizeof flags-strlen(flags),"random-mac ");
        if(flags[0]){ size_t L=strlen(flags); if(L&&flags[L-1]==' ') flags[L-1]=0; field("Flags", flags, width); }
    }
    unsigned int dns=dns_server_addr(); char dnss[32]; struct in_addr da; da.s_addr=dns;
    inet_ntop(AF_INET,&da,dnss,sizeof dnss);
    char self[160];
    if(self_device_name(self,sizeof self)){
        char mymac[20]; mac_str(g_mymac,mymac);
        char myip[32]; struct in_addr sa; sa.s_addr=g_myip; inet_ntop(AF_INET,&sa,myip,sizeof myip);
        printf("\n%-15s %s\n", myip, mymac);
        char sn[160]; snprintf(sn,sizeof sn,"%s",self); clean(sn);
        field("Name", sn, width);
        field("Flags", "this device", width);
    }
    printf("\n(%d hosts)", g_nhost);
    if(dns) printf("  dns %s", dnss);
    printf("\n");
}
