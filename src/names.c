/* names.c - persistent per-MAC device names ("aa:bb:cc:dd:ee:ff<TAB>label") */
#include "lanternet.h"

/* split one line into key and value, stripping the line ending.
   0 if the line has no tab. */
static int split_line(char *line,char *key,int ksz,char *val,int vsz){
    char *tab=strchr(line,'\t');
    if(!tab) return 0;
    *tab=0;
    snprintf(key,(size_t)ksz,"%s",line);
    snprintf(val,(size_t)vsz,"%s",tab+1);
    size_t L=strlen(val);
    while(L && (val[L-1]=='\n' || val[L-1]=='\r')) val[--L]=0;
    return 1;
}

int name_lookup(const unsigned char *mac, char *out, int n){
    char ms[NAME_KEY_LEN]; mac_str(mac,ms);
    FILE *f=fopen(NAMES_FILE,"r");
    if(!f) return 0;
    char line[256], key[NAME_KEY_LEN], val[NAME_VAL_LEN];
    int ok=0;
    while(fgets(line,sizeof line,f)){
        if(!split_line(line,key,sizeof key,val,sizeof val)) continue;
        if(!strcmp(key,ms)){ snprintf(out,(size_t)n,"%s",val); ok=1; break; }
    }
    fclose(f);
    return ok;
}

void name_set(const unsigned char *mac, const char *label){
    char ms[NAME_KEY_LEN]; mac_str(mac,ms);
    static char keys[NAME_MAX_ENTRIES][NAME_KEY_LEN];
    static char vals[NAME_MAX_ENTRIES][NAME_VAL_LEN];
    int n=0;

    FILE *f=fopen(NAMES_FILE,"r");
    if(f){
        char line[256];
        while(fgets(line,sizeof line,f) && n<NAME_MAX_ENTRIES){
            if(!split_line(line,keys[n],NAME_KEY_LEN,vals[n],NAME_VAL_LEN)) continue;
            n++;
        }
        fclose(f);
    }
    int found=0;
    for(int i=0;i<n;i++) if(!strcmp(keys[i],ms)){
        snprintf(vals[i],NAME_VAL_LEN,"%s",label); found=1; break;
    }
    if(!found && n<NAME_MAX_ENTRIES){
        snprintf(keys[n],NAME_KEY_LEN,"%s",ms);
        snprintf(vals[n],NAME_VAL_LEN,"%s",label);
        n++;
    }

    f=fopen(NAMES_FILE,"w");
    if(!f){ perror(NAMES_FILE); return; }
    for(int i=0;i<n;i++) fprintf(f,"%s\t%s\n",keys[i],vals[i]);
    fclose(f);
}
