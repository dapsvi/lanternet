/* netbios.c - NetBIOS name service queries (older Windows-ish devices) */
#include "lanternet.h"

void nbns_probe(int fd, unsigned int ip){
    unsigned char q[50]; memset(q,0,sizeof q);
    q[0]=0x12; q[1]=0x34; q[2]=0x01; q[3]=0x10;
    q[4]=0; q[5]=1;
    q[12]=0x20;
    memcpy(q+13,"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",32);
    q[45]=0x00; q[46]=0x00; q[47]=0x21; q[48]=0x00; q[49]=0x01;
    struct sockaddr_in d; memset(&d,0,sizeof d);
    d.sin_family=AF_INET; d.sin_port=htons(137); d.sin_addr.s_addr=ip;
    if(g_dry) return;
    sendto(fd,q,50,0,(struct sockaddr*)&d,sizeof d);
}

static void nbstat_names(const unsigned char *r,int rdl,unsigned int from);

void nbns_parse(const unsigned char *p,int n,unsigned int from){
    if(n<12) return;
    int qd=(p[4]<<8)|p[5], an=(p[6]<<8)|p[7];
    int off=12;
    for(int i=0;i<qd;i++){ off=dns_skip_name(p,n,off); if(off<0) return; off+=4; }
    for(int i=0;i<an && off+12<=n;i++){
        off=dns_skip_name(p,n,off);
        if(off<0 || off+10>n) return;
        int type=(p[off]<<8)|p[off+1];
        int rdl=(p[off+8]<<8)|p[off+9];
        off+=10;
        if(off+rdl>n) return;
        if(type==0x0021 && rdl>=18) nbstat_names(p+off,rdl,from);
        off+=rdl;
    }
}

/* one entry per name: 15 bytes of name, a suffix byte, 2 flag bytes.
   Take the workstation entry (suffix 0), skipping the __MSBROWSE__ group. */
static void nbstat_names(const unsigned char *r,int rdl,unsigned int from){
    int cnt=r[0];
    for(int i=0;i<cnt;i++){
        int o=1+i*18;
        if(o+18>rdl) return;
        if(r[o+15]!=0x00) continue;                    /* not the workstation name */
        if(r[o]==0x01) continue;                       /* <01><02>__MSBROWSE__ */
        char nm[16]; memcpy(nm,r+o,15); nm[15]=0;
        for(int k=14;k>=0;k--){ if(nm[k]==' '||nm[k]==0) nm[k]=0; else break; }
        if(!nm[0]) continue;
        int ok=1;
        for(int k=0;nm[k];k++) if(!isprint((unsigned char)nm[k])) ok=0;
        if(!ok) continue;
        int hi=find_host(from);
        if(hi>=0 && !g_hosts[hi].name[0] && g_hosts[hi].name_src<2) host_set_name(hi,nm,SRC_NBNS);
        return;
    }
}
