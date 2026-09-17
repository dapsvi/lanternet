/* jsonlite.h - a tiny JSON value tree, parser and string builder */
#ifndef JSONLITE_H
#define JSONLITE_H
#include <stddef.h>

enum { JNULL, JBOOL, JNUM, JSTR, JARR, JOBJ };

typedef struct jval {
    int  t;
    int  b;            /* bool */
    double num;
    char *s;           /* string (JSTR) */
    struct jval **it;  /* array/object members */
    char **key;        /* object keys */
    int  n;            /* member count */
} jval;

jval *jparse(const char *s);       /* returns NULL on error */
void  jfree(jval *v);
jval *jget(const jval *o,const char *k);   /* object lookup, NULL if absent */
const char *jstr(const jval *v);           /* "" if not a string */
double jnum(const jval *v);
int    jlen(const jval *v);
jval  *jat(const jval *v,int i);

/* growable output buffer */
typedef struct { char *b; size_t n, cap; } jbuf;
void jb_init(jbuf *j);
void jb_free(jbuf *j);
void jb_raw(jbuf *j,const char *s);        /* append bytes verbatim */
void jb_puts(jbuf *j,const char *s);       /* append a quoted, escaped string */
void jb_printf(jbuf *j,const char *fmt,...);

#endif
