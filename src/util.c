/* util.c - small helpers */
#include "lanternet.h"

void mac_str(const unsigned char *m, char *b){
    snprintf(b,18,"%02x:%02x:%02x:%02x:%02x:%02x",m[0],m[1],m[2],m[3],m[4],m[5]);
}

/* "aa:bb:cc:dd:ee:ff" -> 6 bytes. 1 on success, 0 if it does not parse. */
int parse_mac(const char *s, unsigned char *out){
    if(!s) return 0;
    unsigned m[6];
    if(sscanf(s,"%x:%x:%x:%x:%x:%x",&m[0],&m[1],&m[2],&m[3],&m[4],&m[5])!=6) return 0;
    for(int i=0;i<6;i++) out[i]=(unsigned char)m[i];
    return 1;
}

unsigned long now_ms(void){
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC,&ts);
    return (unsigned long)ts.tv_sec*1000UL + ts.tv_nsec/1000000UL;
}

/* crude OS hint from the observed IP TTL */
const char *ttl_hint(int ttl){
    if(ttl <= 0)  return "";
    if(ttl <= 64) return "unix";
    if(ttl <= 128) return "windows";
    return "network";
}

const char *find_ci(const char *hay,const char *needle){
    size_t nl=strlen(needle);
    for(const char *p=hay;*p;p++)
        if(!strncasecmp(p,needle,nl)) return p;
    return NULL;
}

/* reject opaque machine identifiers (e.g. a 32-hex KDE Connect / service
   instance id) so they are not shown as if they were a device name */
int name_is_junk(const char *s){
    if(!s || strlen(s)<16) return 0;
    for(const char *p=s;*p;p++)
        if(!isxdigit((unsigned char)*p)) return 0;
    return 1;
}
