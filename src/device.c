/* device.c */
#include "lanternet.h"

static int junk_text(const char *s){
    if(!s[0]) return 1;
    if(!strcmp(s,"null")||!strcmp(s,"0")||!strcmp(s,"localhost")) return 1;
    static const char *bad[]={"failure","exception","cmd:","error","permission",
                              "denied","unknown","not found","failed","usage",NULL};
    for(int i=0;bad[i];i++) if(find_ci(s,bad[i])) return 1;
    return 0;
}

static int read_setting_file(const char *path,const char *key,char *out,int n){
    FILE *f=fopen(path,"r");
    if(!f) return 0;
    char pat[96]; snprintf(pat,sizeof pat,"name=\"%s\"",key);
    char line[4096];
    while(fgets(line,sizeof line,f)){
        if(!find_ci(line,pat)) continue;
        const char *v=find_ci(line,"value=\"");
        if(!v) continue;
        v+=7;
        const char *e=strchr(v,'"');
        if(!e) continue;
        int L=(int)(e-v); if(L>n-1) L=n-1;
        memcpy(out,v,(size_t)L); out[L]=0;
        fclose(f);
        return !junk_text(out);
    }
    fclose(f);
    return 0;
}

int self_device_name(char *out,int n){
    static const char *cmds[]={
        "settings get secure bluetooth_name 2>/dev/null",
        "settings get global device_name 2>/dev/null",
        "settings get secure device_name 2>/dev/null",
        "getprop net.hostname 2>/dev/null",
        "hostname 2>/dev/null"};
    for(unsigned i=0;i<sizeof cmds/sizeof cmds[0];i++){
        FILE *p=popen(cmds[i],"r");
        if(!p) continue;
        char line[160]="";
        if(fgets(line,sizeof line,p)) line[strcspn(line,"\n")]=0;
        pclose(p);
        if(!junk_text(line)){ snprintf(out,n,"%s",line); return 1; }
    }
    static const struct { const char *path,*key; } files[]={
        {"/data/system/users/0/settings_secure.xml","bluetooth_name"},
        {"/data/system/users/0/settings_global.xml","device_name"},
        {"/data/system/users/0/settings_system.xml","device_name"}};
    for(unsigned i=0;i<sizeof files/sizeof files[0];i++)
        if(read_setting_file(files[i].path,files[i].key,out,n)) return 1;
    return 0;
}
