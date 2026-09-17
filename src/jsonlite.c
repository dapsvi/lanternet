/* jsonlite.c - see jsonlite.h */
#include "jsonlite.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

static jval *jnew(int t){
    jval *v=calloc(1,sizeof *v);
    if(v) v->t=t;
    return v;
}

void jfree(jval *v){
    if(!v) return;
    free(v->s);
    for(int i=0;i<v->n;i++){ jfree(v->it[i]); free(v->key? v->key[i]:NULL); }
    free(v->it); free(v->key); free(v);
}

typedef struct { const char *p; } P;
static void skip(P*x){ while(*x->p && (unsigned char)*x->p<=32) x->p++; }

static void utf8(char **o,unsigned cp){
    if(cp<0x80){ *(*o)++=(char)cp; }
    else if(cp<0x800){ *(*o)++=(char)(0xC0|(cp>>6)); *(*o)++=(char)(0x80|(cp&0x3F)); }
    else { *(*o)++=(char)(0xE0|(cp>>12)); *(*o)++=(char)(0x80|((cp>>6)&0x3F)); *(*o)++=(char)(0x80|(cp&0x3F)); }
}

static char *pstring(P*x){
    if(*x->p!='"') return NULL;
    x->p++;
    size_t cap=32,n=0; char *o=malloc(cap);
    if(!o) return NULL;
    while(*x->p && *x->p!='"'){
        char c=*x->p++;
        if(c=='\\'){
            char e=*x->p++;
            switch(e){
                case 'n': c='\n'; break;  case 't': c='\t'; break;
                case 'r': c='\r'; break;  case 'b': c='\b'; break;
                case 'f': c='\f'; break;  case '/': c='/';  break;
                case '"': c='"';  break;  case '\\': c='\\'; break;
                case 'u': {
                    unsigned cp=0;
                    for(int k=0;k<4 && *x->p;k++){
                        char h=*x->p++; cp<<=4;
                        if(h>='0'&&h<='9') cp|=h-'0';
                        else if(h>='a'&&h<='f') cp|=h-'a'+10;
                        else if(h>='A'&&h<='F') cp|=h-'A'+10;
                    }
                    if(n+4>cap){ cap=cap*2+8; o=realloc(o,cap); }
                    utf8(&o,cp);
                    continue;
                }
                default: c=e; break;
            }
        }
        if(n+1>=cap){ cap=cap*2+8; char *nn=realloc(o,cap); if(!nn){ free(o); return NULL; } o=nn; }
        o[n++]=c;
    }
    if(*x->p!='"'){ free(o); return NULL; }
    x->p++;
    o[n]=0;
    return o;
}

static jval *pval(P*x){
    skip(x);
    char c=*x->p;
    if(c=='{'){
        x->p++;
        jval *v=jnew(JOBJ);
        int cap=8; v->it=malloc(sizeof(jval*)*cap); v->key=malloc(sizeof(char*)*cap);
        skip(x);
        if(*x->p=='}'){ x->p++; return v; }
        for(;;){
            skip(x);
            char *k=pstring(x);
            if(!k){ jfree(v); return NULL; }
            skip(x);
            if(*x->p!=':'){ free(k); jfree(v); return NULL; }
            x->p++;
            jval *m=pval(x);
            if(!m){ free(k); jfree(v); return NULL; }
            if(v->n>=cap){ cap*=2; v->it=realloc(v->it,sizeof(jval*)*cap); v->key=realloc(v->key,sizeof(char*)*cap); }
            v->it[v->n]=m; v->key[v->n]=k; v->n++;
            skip(x);
            if(*x->p==','){ x->p++; continue; }
            if(*x->p=='}'){ x->p++; break; }
            jfree(v); return NULL;
        }
        return v;
    }
    if(c=='['){
        x->p++;
        jval *v=jnew(JARR);
        int cap=8; v->it=malloc(sizeof(jval*)*cap);
        skip(x);
        if(*x->p==']'){ x->p++; return v; }
        for(;;){
            jval *m=pval(x);
            if(!m){ jfree(v); return NULL; }
            if(v->n>=cap){ cap*=2; v->it=realloc(v->it,sizeof(jval*)*cap); }
            v->it[v->n++]=m;
            skip(x);
            if(*x->p==','){ x->p++; continue; }
            if(*x->p==']'){ x->p++; break; }
            jfree(v); return NULL;
        }
        return v;
    }
    if(c=='"'){ jval *v=jnew(JSTR); v->s=pstring(x); if(!v->s){ jfree(v); return NULL; } return v; }
    if(!strncmp(x->p,"true",4)){ x->p+=4; jval *v=jnew(JBOOL); v->b=1; return v; }
    if(!strncmp(x->p,"false",5)){ x->p+=5; jval *v=jnew(JBOOL); v->b=0; return v; }
    if(!strncmp(x->p,"null",4)){ x->p+=4; return jnew(JNULL); }
    if(c=='-'||(c>='0'&&c<='9')){
        char *end; double d=strtod(x->p,&end);
        if(end==x->p) return NULL;
        x->p=end; jval *v=jnew(JNUM); v->num=d; return v;
    }
    return NULL;
}

jval *jparse(const char *s){
    P x={s};
    jval *v=pval(&x);
    if(!v) return NULL;
    skip(&x);
    if(*x.p){ jfree(v); return NULL; }   /* trailing garbage */
    return v;
}

jval *jget(const jval *o,const char *k){
    if(!o||o->t!=JOBJ) return NULL;
    for(int i=0;i<o->n;i++) if(o->key[i]&&!strcmp(o->key[i],k)) return o->it[i];
    return NULL;
}
const char *jstr(const jval *v){ return (v&&v->t==JSTR&&v->s)?v->s:""; }
double jnum(const jval *v){ return (v&&v->t==JNUM)?v->num:0; }
int jlen(const jval *v){ return (v&&(v->t==JARR||v->t==JOBJ))?v->n:0; }
jval *jat(const jval *v,int i){ return (v&&(v->t==JARR||v->t==JOBJ)&&i>=0&&i<v->n)?v->it[i]:NULL; }

/* ---- builder ------------------------------------------------------------- */
void jb_init(jbuf *j){ j->b=malloc(256); j->n=0; j->cap=256; if(j->b) j->b[0]=0; }
void jb_free(jbuf *j){ free(j->b); j->b=NULL; j->n=j->cap=0; }

static void jb_room(jbuf *j,size_t extra){
    if(j->n+extra+1<=j->cap) return;
    while(j->n+extra+1>j->cap) j->cap=j->cap?j->cap*2:256;
    j->b=realloc(j->b,j->cap);
}
void jb_raw(jbuf *j,const char *s){
    if(!j->b) return;
    size_t L=strlen(s);
    jb_room(j,L); memcpy(j->b+j->n,s,L); j->n+=L; j->b[j->n]=0;
}
void jb_printf(jbuf *j,const char *fmt,...){
    if(!j->b) return;
    char tmp[1024];
    va_list ap; va_start(ap,fmt);
    int k=vsnprintf(tmp,sizeof tmp,fmt,ap);
    va_end(ap);
    if(k<0) return;
    if((size_t)k<sizeof tmp){ jb_raw(j,tmp); return; }
    char *big=malloc((size_t)k+1);
    if(!big) return;
    va_start(ap,fmt); vsnprintf(big,(size_t)k+1,fmt,ap); va_end(ap);
    jb_raw(j,big); free(big);
}
void jb_puts(jbuf *j,const char *s){
    if(!j->b) return;
    jb_raw(j,"\"");
    for(const unsigned char *p=(const unsigned char*)(s?s:"");*p;p++){
        unsigned char c=*p;
        if(c=='"'||c=='\\'){ char t[3]={'\\',(char)c,0}; jb_raw(j,t); }
        else if(c=='\n') jb_raw(j,"\\n");
        else if(c=='\t') jb_raw(j,"\\t");
        else if(c=='\r') jb_raw(j,"\\r");
        else if(c<0x20){ char t[8]; snprintf(t,sizeof t,"\\u%04x",c); jb_raw(j,t); }
        else { char t[2]={(char)c,0}; jb_raw(j,t); }
    }
    jb_raw(j,"\"");
}
