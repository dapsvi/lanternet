/* actions.h - the registry of live cut actions (selector -> persistent cut) */
#ifndef ACTIONS_H
#define ACTIONS_H
#include "lanternet.h"

#define MAX_ACTION 64

struct action {
    int  id;
    char sel[256];        /* "" means every device */
    int  active;
    unsigned long born_ms;
};

void  actions_init(void);
int   action_add(const char *sel);            /* returns id, -1 if full */
int   action_stop_id(int id);                 /* 1 if removed */
int   action_stop_sel(const char *sel);       /* count removed */
int   action_stop_all(void);                  /* count removed */
int   actions_active(void);
struct action *action_at(int i);              /* i-th active action or NULL */

/* would any live action cut this host? */
int   action_wants(const struct host *h);

#endif
