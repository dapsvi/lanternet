/* cache.c - persistent per-MAC name cache */
#include "lanternet.h"

void cache_load(void){
    FILE *f=fopen(CACHE_FILE,"r");
    if(!f) return;
    char line[256];
    while(fgets(line,sizeof line,f)){
        char ms[32], nm[128]; int src=0;
        if(sscanf(line,"%31s %d %127[^\n]",ms,&src,nm)!=3) continue;
        if(name_is_junk(nm)) continue;
        unsigned char mac[6];
        if(!parse_mac(ms,mac)) continue;
        for(int i=0;i<g_nhost;i++)
            if(!memcmp(g_hosts[i].mac,mac,6) && !g_hosts[i].name[0]){
                memcpy(g_hosts[i].name,nm,sizeof g_hosts[i].name);
                g_hosts[i].name[sizeof g_hosts[i].name-1]=0;
                g_hosts[i].name_src=9;
                break;
            }
    }
    fclose(f);
}

void cache_save(void){
    char tmp[256];
    snprintf(tmp,sizeof tmp,"%s.tmp",CACHE_FILE);
    FILE *f=fopen(tmp,"w");
    if(!f) return;
    for(int i=0;i<g_nhost;i++){
        int s=g_hosts[i].name_src;
        if(!g_hosts[i].name[0] || s<2) continue;
        char ms[20]; mac_str(g_hosts[i].mac,ms);
        fprintf(f,"%s %d %s\n", ms, s, g_hosts[i].name);
    }
    fclose(f);
    rename(tmp,CACHE_FILE);
}
