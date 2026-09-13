/* lanternet.h - shared types, globals and the module interfaces.
 *
 * Layout of the source:
 *
 *   main.c      globals, argument parsing, entry point
 *   commands.c  the commands: help, setup levels, handlers, long-running loops
 *   net.c       interface/IP/gateway detection, the raw socket
 *   packet.c    frame builders: ARP, ICMP, ICMPv6, checksums
 *   scan.c      host table, ARP sweep, neighbour merge, gateway MAC, orchestration
 *   icmp.c      ICMP echo (TTL/OS hint) + ICMPv6 echo (IPv6 presence)
 *   netbios.c   NetBIOS name service queries
 *   mdns.c      mDNS: A/PTR parsing, reverse lookups, service browsing
 *   ssdp.c      SSDP/UPnP discovery, friendlyName fetch
 *   dhcp.c      passive DHCP sniffing, local lease files
 *   dns.c       DNS helpers, LAN resolver discovery, batched PTR
 *   cache.c     persistent per-MAC name cache
 *   device.c    this device's own name
 *   json.c      output: text blocks and JSON
 *   names.c     user-set per-MAC names
 *   attacks.c   poison, restore, state file
 *   oui.c       vendor lookup over the generated OUI table
 *   util.c      small helpers
 */
#ifndef LANTERNET_H
#define LANTERNET_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <dirent.h>
#include <fcntl.h>
#include <strings.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/uio.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <ifaddrs.h>

#define LANTERNET_VERSION "0.1.0"
#define MAXHOST 4096
#ifdef __ANDROID__
#define RUNDIR     "/data/local/tmp"
#else
#define RUNDIR     "/tmp"
#endif
#define NAMES_FILE RUNDIR "/lanternet.names"
#define STATE_FILE RUNDIR "/lanternet.state"
#define PID_FILE   RUNDIR "/lanternet.pid"
#define CACHE_FILE RUNDIR "/lanternet.cache"
#define TICK_US    700000            /* NetCut-compatible poison cadence */

/* name_src values: where a hostname came from */
#define SRC_NONE   0
#define SRC_USER   1
#define SRC_NBNS   2
#define SRC_MDNS   3
#define SRC_DNS    4
#define SRC_LEASE  5
#define SRC_MDNSVC 6
#define SRC_SSDP   7
#define SRC_DHCP   8
#define SRC_CACHE  9

/* tuning: the numbers that used to be bare in the code */
#define SWEEP_CAP        1024       /* hosts per pass unless --all */
#define SWEEP_BATCH      128        /* ARP sends between socket drains */
#define ARP_QUIET_WIN    5          /* empty receive windows that end a sweep */
#define SSDP_MAX_LOC     16         /* SSDP LOCATION urls per probe */
#define NAME_MAX_ENTRIES 512        /* names.c saved-name table */
#define NAME_KEY_LEN     20         /* "aa:bb:cc:dd:ee:ff" + NUL */
#define NAME_VAL_LEN     80
#define CONSOLE_MIN      40         /* text output width clamp */
#define CONSOLE_MAX      200
#define CONSOLE_DEFAULT  80
#define DHCP_OPT_HOSTNAME 12        /* option 12 */
#define DHCP_OPT_VENDOR   60        /* option 60 */

struct host {
    unsigned int ip;
    unsigned char mac[6];
    int cut;
    char vendor[64];
    char name[64];          /* resolved or user-set */
    char ip6[46];           /* an IPv6 address seen for this MAC, if any */
    int  name_src;          /* one of SRC_* above */
    int  ttl;               /* ICMP TTL -> OS hint */
    int  v6;                /* answered ICMPv6 on its derived link-local */
};

/* ARP payload as it sits in the frame, 14 bytes into the Ethernet header */
struct arp_hdr {
    unsigned short htype, ptype;
    unsigned char  hlen, plen;
    unsigned short op;
    unsigned char  sha[6];
    unsigned int   spa;
    unsigned char  tha[6];
    unsigned int   tpa;
} __attribute__((packed));

extern struct host g_hosts[MAXHOST];
extern int g_nhost;
extern int g_sock, g_ifidx;
extern unsigned char g_mymac[6], g_gwmac[6], g_router_ll[16];
extern unsigned int g_myip, g_gwip, g_mask;
extern char g_ifname[64];
extern int g_do_v4, g_do_v6, g_v6_ok, g_scan_all, g_dry, g_use_fake, g_json;
extern unsigned char g_fake_mac[6];
extern int g_guard_pid;              /* --guard: exit when this pid disappears */

#ifdef LANTERNET_APP
/* app build: no background modes, and every long run repairs on the way out */
extern volatile sig_atomic_t g_stop;
void app_install_signals(void);
void app_guard_check(void);
void app_cleanup_exit(const char *why) __attribute__((noreturn));
#endif

/* util.c */
void mac_str(const unsigned char *, char *);
const char *ttl_hint(int ttl);
unsigned long now_ms(void);
const char *find_ci(const char *hay, const char *needle);
int name_is_junk(const char *s);
int parse_mac(const char *s, unsigned char *out);

/* oui.c */
const char *vendor_of(const unsigned char *);

/* names.c - user-set names, keyed by MAC */
int  name_lookup(const unsigned char *, char *, int);
void name_set(const unsigned char *, const char *);

/* net.c */
int  iface_index(const char *);
void find_default_iface(char *, size_t, unsigned int *);
unsigned int gw_via_ip_cmd(void);
void get_iface_info(const char *);
int  open_raw(void);
int  have_link(void);
int  setup_network(void);

/* packet.c */
unsigned short inet_csum(const unsigned char *, int);
unsigned short icmp6_csum(const unsigned char *, const unsigned char *, const unsigned char *, int);
void send_frame(const unsigned char *, const unsigned char *, const unsigned char *, int, unsigned short);
void send_arp(int, const unsigned char *, unsigned int, const unsigned char *, unsigned int, const unsigned char *);
void eui64_ll(const unsigned char *, unsigned char ll[16]);
int  router_ll_from_route(unsigned char ll[16]);
void ndp_na(const unsigned char *, const unsigned char *, const unsigned char *, const unsigned char *, const unsigned char *, const unsigned char *);
void ndp_poison(const struct host *, int);

/* main.c / commands.c - the command line */
void cli_usage(void);
int  cli_run(const char *cmd, int narg, const char *arg[]);

/* scan.c */
void add_host(unsigned int, const unsigned char *);
int  find_host(unsigned int);
void host_set_name(int idx, const char *name, int src);
int  recv_arp(int ms);
int  arp_from_file(unsigned int, unsigned char *);
int  arp_probe(unsigned int, unsigned char *);
int  resolve_ip(unsigned int, unsigned char *);
void load_gwmac(void);
void merge_neigh(void);
void rescan_hosts(void);
void host_sort(void);
void arp_sweep(void);
void scan(void);
void listen_names(int secs);

/* icmp.c */
int  icmp_open(void);
void icmp_echo(int s, unsigned int ip, unsigned short id);
void icmp_handle(int s);
int  icmp6_open(void);
void icmp6_echo(int s, const unsigned char *dst_ll, unsigned short id);
void icmp6_handle(int s);

/* netbios.c */
void nbns_probe(int fd, unsigned int ip);
void nbns_parse(const unsigned char *p, int n, unsigned int from);

/* mdns.c */
int  mdns_open(void);
void mdns_reverse(int s, unsigned int ip);
void mdns_parse(const unsigned char *p, int n);
void mdns_browse(void);

/* ssdp.c */
void ssdp_probe(void);

/* dhcp.c */
void dhcp_listen(int ms);
void merge_dhcp_leases(void);

/* dns.c */
int  dns_skip_name(const unsigned char *p, int n, int off);
int  dns_read_name(const unsigned char *p, int n, int off, char *out, int osz);
int  dns_enc_name(unsigned char *b, int max, const char *name);
unsigned int dns_server_addr(void);
void dns_batch_ptr(int ms);

/* cache.c */
void cache_load(void);
void cache_save(void);

/* device.c */
int  self_device_name(char *out, int n);

/* json.c */
void print_hosts(void);
const char *name_source(int src);

/* attacks.c */
void poison(const struct host *, int);
void self_keepalive(void);
void state_save(void);
void state_restore(void);
void garp_announce(unsigned int, const unsigned char *);
void fix_host(unsigned int, const unsigned char *);
void restore_run(void);
int  read_pidfile(void);

#endif
