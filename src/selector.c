/* selector.c - boolean selectors over the device table */
#include "selector.h"

static const char *P;
static int g_bad;

static void skipws(void){ while(*P==' '||*P=='\t') P++; }

/* tagged bits we can match on, computed from the live table */
void host_tags(const struct host *h, char *out, int n){
    out[0]=0;
    #define ADD(t) do{ if(out[0]) snprintf(out+strlen(out), (size_t)(n-(int)strlen(out)), ",%s", t); \
                       else snprintf(out,(size_t)n,"%s",t); }while(0)
    if(h->mac[0]&0x02) ADD("random-mac");
    if(h->v6)          ADD("v6");
    if(h->ip==g_gwip)  ADD("gateway");
    if(h->ip==g_myip)  ADD("self");
    #undef ADD
}

static int has_in(const char *hay,const char *needle){ return find_ci(hay,needle)!=NULL; }

static int field_match(const struct host *h,const char *tok){
    char field[16]="", val[256];
    const char *c=strchr(tok,':');
    if(c){
        size_t L=(size_t)(c-tok);
        if(L<sizeof field){ memcpy(field,tok,L); field[L]=0; }
        snprintf(val,sizeof val,"%s",c+1);
    } else snprintf(val,sizeof val,"%s",tok);

    char mac[20]; mac_str(h->mac,mac);
    char ip[32]; struct in_addr a; a.s_addr=h->ip;
    snprintf(ip,sizeof ip,"%s",inet_ntoa(a));
    char tags[64]; host_tags(h,tags,sizeof tags);

    int known = !field[0] || !strcasecmp(field,"ip") || !strcasecmp(field,"mac") ||
                !strcasecmp(field,"name") || !strcasecmp(field,"brand") ||
                !strcasecmp(field,"tag");
    if(!known){ field[0]=0; snprintf(val,sizeof val,"%s",tok); } /* "aa:bb" is a mac, not a field */

    if(!field[0])
        return has_in(ip,val)||has_in(mac,val)||has_in(h->name,val)||
               has_in(h->vendor,val)||has_in(tags,val);
    if(!strcasecmp(field,"ip"))    return has_in(ip,val);
    if(!strcasecmp(field,"mac"))   return has_in(mac,val);
    if(!strcasecmp(field,"name"))  return has_in(h->name,val)||has_in(h->vendor,val);
    if(!strcasecmp(field,"brand")) return has_in(h->vendor,val);
    if(!strcasecmp(field,"tag"))  return has_in(tags,val);
    return 0;
}

static int eval_or(const struct host *h);

static int atom(const struct host *h){
    char tok[256]; int n=0;
    while(*P && *P!=' ' && *P!='\t' && *P!='(' && *P!=')' && *P!='&' && *P!='|'){
        if(n<(int)sizeof tok-1) tok[n++]=*P;
        P++;
    }
    tok[n]=0;
    if(n==0){ g_bad=1; return 0; }
    return field_match(h,tok);
}

static int eval_primary(const struct host *h){
    skipws();
    if(*P=='!'){ P++; return !eval_primary(h); }
    if(*P=='('){ P++; int r=eval_or(h); skipws(); if(*P==')') P++; return r; }
    return atom(h);
}

/* peek whether the next token is the operator word `w` (standalone) */
static int peek_word(const char *w){
    const char *q=P;
    size_t L=strlen(w);
    if(strncasecmp(q,w,L)) return 0;
    char nx=q[L];
    if(nx && nx!=' ' && nx!='\t' && nx!='(' && nx!='!') return 0;
    P=q+L; return 1;
}

static int eval_and(const struct host *h){
    int r=eval_primary(h);
    for(;;){
        skipws();
        if(P[0]=='&'&&P[1]=='&'){ P+=2; int w=eval_primary(h); r=r&&w; continue; }
        if(peek_word("and")){ int w=eval_primary(h); r=r&&w; continue; }
        break;
    }
    return r;
}

static int eval_or(const struct host *h){
    int r=eval_and(h);
    for(;;){
        skipws();
        if(P[0]=='|'&&P[1]=='|'){ P+=2; int w=eval_and(h); r=r||w; continue; }
        if(peek_word("or")){ int w=eval_and(h); r=r||w; continue; }
        break;
    }
    return r;
}

int sel_match(const struct host *h,const char *sel){
    if(!sel||!sel[0]) return 1;
    P=sel;
    int r=eval_or(h);
    return r;
}

int sel_valid(const char *sel){
    if(!sel||!sel[0]) return 1;
    P=sel; g_bad=0;
    struct host dummy; memset(&dummy,0,sizeof dummy);
    eval_or(&dummy);
    skipws();
    return *P==0 && !g_bad;
}
