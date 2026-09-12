/* oui.c - vendor lookup from the generated 24-bit prefix table */
#include "lanternet.h"
#include "oui_table.h"

const char *vendor_of(const unsigned char *mac){
    unsigned int p = ((unsigned)mac[0]<<16) | ((unsigned)mac[1]<<8) | mac[2];
    int lo=0, hi=OUI_N-1;
    while(lo<=hi){
        int mid=(lo+hi)/2;
        if(OUI[mid].p==p) return OUI[mid].n;
        if(OUI[mid].p<p) lo=mid+1; else hi=mid-1;
    }
    return NULL;
}
