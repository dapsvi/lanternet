/* tui.c - live terminal UI */
#include "lanternet.h"
#include "jsonlite.h"

#ifdef NO_CURSES
int tui_run(void){ fprintf(stderr,"tui: built without ncurses\n"); return 1; }
#else
#include <ncurses.h>

#define MAXROWS 8192
#define POLL_MS 600

struct row { char ip[32],mac[20],name[80],tags[72],state[12]; };
static struct row rows[MAXROWS];
static int  nrows;
static char flt[128];

static char iface[64], myip[32], gw[32], gwmac[20];
static int  hdr_hosts, hdr_paused;
static unsigned long hdr_frames;
static char acts[16][160];
static int  nacts;
static char logline[256]="ready";
static char conn_err[192]="";
static int  sel, vtop;

static jval *call(const char *cmd,const char *selq){
    jbuf j; jb_init(&j);
    jb_raw(&j,"{\"v\":1,\"cmd\":"); jb_puts(&j,cmd);
    jb_raw(&j,",\"sel\":"); if(selq&&selq[0]) jb_puts(&j,selq); else jb_raw(&j,"null");
    jb_raw(&j,",\"state\":null,\"id\":null,\"value\":null}");
    char *line=rpc_raw(j.b?j.b:"{}");
    jb_free(&j);
    if(!line) return NULL;
    jval *v=jparse(line);
    free(line);
    return v;
}

static void fetch(void){
    jval *st=call("status",NULL);
    if(!st){ snprintf(conn_err,sizeof conn_err,"%s", g_rpc_err[0]?g_rpc_err:"server unreachable"); }
    else {
        conn_err[0]=0;
        jval *r=jget(st,"result");
        snprintf(iface,sizeof iface,"%s",jstr(jget(r,"iface")));
        snprintf(myip,sizeof myip,"%s",jstr(jget(r,"myip")));
        snprintf(gw,sizeof gw,"%s",jstr(jget(r,"gw")));
        snprintf(gwmac,sizeof gwmac,"%s",jstr(jget(r,"gwmac")));
        hdr_hosts=(int)jnum(jget(r,"hosts"));
        hdr_frames=(unsigned long)jnum(jget(r,"frames"));
        jval *sp=jget(r,"scan_paused");
        hdr_paused = sp && sp->t==JBOOL && sp->b;
        nacts=0;
        jval *a=jget(r,"actions");
        for(int i=0;i<jlen(a)&&i<16;i++){
            jval *x=jat(a,i);
            snprintf(acts[nacts],sizeof acts[0],"#%.0f  %-28s %3.0f dev  %lus",
                jnum(jget(x,"id")), jstr(jget(x,"sel"))[0]?jstr(jget(x,"sel")):"*",
                jnum(jget(x,"matched")), (unsigned long)jnum(jget(x,"age_s")));
            nacts++;
        }
        jfree(st);
    }
    jval *ls=call("list",flt);
    if(ls){
        jval *r=jget(ls,"result");
        jval *h=jget(r,"hosts");
        nrows=0;
        for(int i=0;i<jlen(h)&&i<MAXROWS;i++){
            jval *x=jat(h,i);
            struct row *w=&rows[nrows];
            snprintf(w->ip,sizeof w->ip,"%s",jstr(jget(x,"ip")));
            snprintf(w->mac,sizeof w->mac,"%s",jstr(jget(x,"mac")));
            const char *nm=jstr(jget(x,"name")); const char *br=jstr(jget(x,"brand"));
            snprintf(w->name,sizeof w->name,"%s", nm[0]?nm:br);
            snprintf(w->state,sizeof w->state,"%s",jstr(jget(x,"state")));
            w->tags[0]=0;
            jval *t=jget(x,"tags");
            for(int k=0;k<jlen(t);k++){ if(k) strncat(w->tags,",",sizeof w->tags-strlen(w->tags)-1);
                strncat(w->tags,jstr(jat(t,k)),sizeof w->tags-strlen(w->tags)-1); }
            nrows++;
        }
        jfree(ls);
    }
}

static void draw(void){
    int H,W; getmaxyx(stdscr,H,W);
    erase();
    attron(A_BOLD|COLOR_PAIR(1));
    mvprintw(0,0,"lanternet  ");
    attroff(A_BOLD|COLOR_PAIR(1));
    if(conn_err[0]){
        attron(A_BOLD|COLOR_PAIR(2));
        printw("NOT CONNECTED: %s",conn_err);
        clrtoeol();
        attroff(A_BOLD|COLOR_PAIR(2));
        mvprintw(1,0," start the server:  sudo lanternet start   (then this refreshes itself)");
        mvhline(2,0,ACS_HLINE,W);
        refresh();
        return;
    }
    printw("%s  ip %s  gw %s (%s)  %d devices  %lu frames  scanner %s",
        iface,myip,gw,gwmac,hdr_hosts,hdr_frames,hdr_paused?"PAUSED":"running");
    if(flt[0]){ attron(COLOR_PAIR(3)); printw("   filter: %s",flt); attroff(COLOR_PAIR(3)); }
    mvhline(1,0,ACS_HLINE,W);

    int acts_top=H-4-nacts;
    if(acts_top<3) acts_top=3;
    int list_top=3, list_rows=acts_top-2;
    attron(A_BOLD);
    mvprintw(2,0,"%-15s %-17s %-9s %-24s %s","IP","MAC","STATE","NAME","TAGS");
    attroff(A_BOLD);
    if(sel>=nrows) sel = nrows?nrows-1:0;
    if(sel<vtop) vtop=sel;
    if(sel>=vtop+list_rows) vtop=sel-list_rows+1;
    for(int i=0;i<list_rows;i++){
        int r=vtop+i; if(r>=nrows) break;
        struct row *w=&rows[r];
        int attr=0;
        if(!strcmp(w->state,"held")) attr=COLOR_PAIR(1);
        else if(!strcmp(w->state,"restoring")) attr=COLOR_PAIR(2);
        if(attr) attron(attr);
        if(r==sel) attron(A_REVERSE);
        mvprintw(list_top+i,0,"%-15s %-17s %-9s %-24s %s",w->ip,w->mac,w->state,w->name,w->tags);
        if(r==sel) attroff(A_REVERSE);
        if(attr) attroff(attr);
    }
    mvhline(acts_top-1,0,ACS_HLINE,W);
    attron(A_BOLD); mvprintw(acts_top-1,W>40?W-12:0,"ACTIONS"); attroff(A_BOLD);
    for(int i=0;i<nacts;i++) mvprintw(acts_top+i,0,"%s",acts[i]);
    if(!nacts) mvprintw(acts_top,0,"(none)");

    attron(A_REVERSE);
    char hint[256];
    snprintf(hint,sizeof hint," c cut  x resume  u stopsel  C stopall  s scan  p pause  / filter  : cmd  r refresh  q quit ");
    mvprintw(H-2,0,"%-*s",W,hint);
    attroff(A_REVERSE);
    char logb[256]; snprintf(logb,sizeof logb," %s",logline);
    mvprintw(H-1,0,"%-*s",W,logb);
    refresh();
}

static char *prompt(const char *label){
    static char buf[160]; buf[0]=0; int n=0;
    int H,W; getmaxyx(stdscr,H,W);
    echo(); curs_set(1);
    mvprintw(H-1,0,"%-*s",W,label);
    move(H-1,(int)strlen(label));
    int ch;
    while((ch=getch())!=ERR){
        if(ch=='\n'||ch=='\r') break;
        if(ch==27||ch==KEY_F(1)){ n=0; break; }
        if(ch==KEY_BACKSPACE||ch==127||ch==8){ if(n) buf[--n]=0; }
        else if(ch>=' '&&n<(int)sizeof(buf)-1){ buf[n++]=(char)ch; buf[n]=0; }
        mvprintw(H-1,0,"%-*s",W,label); mvprintw(H-1,(int)strlen(label),"%s",buf);
        refresh();
    }
    noecho(); curs_set(0);
    buf[n]=0;
    return buf;
}

int tui_run(void){
    initscr(); cbreak(); noecho(); keypad(stdscr,TRUE); curs_set(0);
    if(has_colors()){ start_color(); use_default_colors();
        init_pair(1,COLOR_GREEN,-1); init_pair(2,COLOR_YELLOW,-1); init_pair(3,COLOR_CYAN,-1); }
    nodelay(stdscr,TRUE);
    flt[0]=0; sel=0; vtop=0; nrows=0; nacts=0;

    for(;;){
        fetch();
        draw();
        int waited=0, ch;
        while(waited<POLL_MS){
            ch=getch();
            if(ch==ERR){ napms(50); waited+=50; continue; }
            if(ch=='q') goto done;
            if(ch=='r'){ snprintf(logline,sizeof logline,"refreshed"); break; }
            if(ch==KEY_DOWN||ch=='j'){ if(sel<nrows-1) sel++; draw(); }
            else if(ch==KEY_UP||ch=='k'){ if(sel>0) sel--; draw(); }
            else if(ch==KEY_NPAGE){ sel+=10; if(sel>=nrows) sel=nrows?nrows-1:0; draw(); }
            else if(ch==KEY_PPAGE){ sel-=10; if(sel<0) sel=0; draw(); }
            else if(ch=='c'){ if(nrows){ char s[40]; snprintf(s,sizeof s,"ip:%s",rows[sel].ip);
                    jval *v=call("cut",s); if(v) jfree(v); snprintf(logline,sizeof logline,"cut %s",rows[sel].ip); } }
            else if(ch=='x'){ if(nrows){ char s[40]; snprintf(s,sizeof s,"ip:%s",rows[sel].ip);
                    jval *v=call("resume",s); if(v) jfree(v); snprintf(logline,sizeof logline,"resume %s",rows[sel].ip); } }
            else if(ch=='C'){ jval *v=call("stopall",NULL); if(v) jfree(v); snprintf(logline,sizeof logline,"stopped all"); }
            else if(ch=='u'){ if(nrows){ char s[40]; snprintf(s,sizeof s,"ip:%s",rows[sel].ip);
                    jval *v=call("stop",s); if(v) jfree(v); snprintf(logline,sizeof logline,"stopped action on %s",rows[sel].ip); } }
            else if(ch=='s'){ jval *v=call("scan",NULL);
                    snprintf(logline,sizeof logline, v?"fast scan requested":(conn_err[0]?conn_err:"scan failed"));
                    if(v) jfree(v); }
            else if(ch=='p'){ jval *v=call(hdr_paused?"scanresume":"scanpause",NULL); if(v) jfree(v); }
            else if(ch=='/'||ch==':'){ char lab[8]; snprintf(lab,sizeof lab,"%c ",ch); char *in=prompt(lab);
                    if(ch=='/'){ snprintf(flt,sizeof flt,"%s",in); snprintf(logline,sizeof logline,"filter: %s",flt[0]?flt:"(none)"); }
                    else if(in[0]){ char cmd[40]="",sel2[128]=""; sscanf(in,"%39s %127[^\n]",cmd,sel2);
                        jval *v=call(cmd,sel2); if(v) jfree(v); snprintf(logline,sizeof logline,"%s",in); } }
            else if(ch==KEY_RESIZE) draw();
        }
    }
done:
    endwin();
    return 0;
}
#endif
