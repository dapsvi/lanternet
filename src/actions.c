/* actions.c - the registry of live cut actions */
#include "actions.h"
#include "selector.h"

static struct action A[MAX_ACTION];
static int next_id=1;

void actions_init(void){ memset(A,0,sizeof A); next_id=1; }

int action_add(const char *sel){
    for(int i=0;i<MAX_ACTION;i++){
        if(A[i].active) continue;
        A[i].active=1;
        A[i].id=next_id++;
        snprintf(A[i].sel,sizeof A[i].sel,"%s",sel?sel:"");
        A[i].born_ms=now_ms();
        return A[i].id;
    }
    return -1;
}

int action_stop_id(int id){
    for(int i=0;i<MAX_ACTION;i++)
        if(A[i].active && A[i].id==id){ A[i].active=0; return 1; }
    return 0;
}

int action_stop_sel(const char *sel){
    int n=0;
    for(int i=0;i<MAX_ACTION;i++)
        if(A[i].active && !strcmp(A[i].sel,sel?sel:"")){ A[i].active=0; n++; }
    return n;
}

int action_stop_all(void){
    int n=0;
    for(int i=0;i<MAX_ACTION;i++) if(A[i].active){ A[i].active=0; n++; }
    return n;
}

int actions_active(void){
    int n=0;
    for(int i=0;i<MAX_ACTION;i++) if(A[i].active) n++;
    return n;
}

struct action *action_at(int i){
    if(i<0||i>=MAX_ACTION||!A[i].active) return NULL;
    return &A[i];
}

int action_wants(const struct host *h){
    for(int i=0;i<MAX_ACTION;i++)
        if(A[i].active && sel_match(h,A[i].sel)) return 1;
    return 0;
}
