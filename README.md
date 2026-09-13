# lanternet

Small C tool for working on a LAN. It maps what's on the network, and it can
cut a device off it.

The cut is ARP poisoning in both directions: I tell the victim that the gateway
lives at my MAC, and tell the gateway that the victim lives at my MAC. At the
700 ms cadence it holds for as long as I keep sending. The IPv6 half does the
same thing with neighbour advertisements, so a dual-stack device loses both
paths. `restore` sends the corrective packets and fixes up the gateway too.

Made for GNU/Linux and Android (root).

## Build

    make             Linux binary  -> ./lanternet-linux
    make android     Android arm64 -> ./lanternet
    make android-app Android arm64 -> ./lanternet-app   (the APK build, below)
    make check       recompile with a much stricter warning set

`make android` needs an NDK. Anything from about r21 onwards works, since the
program only uses libc. The Makefile looks where it is usually installed:

    $ANDROID_NDK_ROOT   $ANDROID_NDK_HOME
    $ANDROID_HOME/ndk   $ANDROID_SDK_ROOT/ndk
    ~/Android/Sdk/ndk   ~/Library/Android/sdk/ndk
    /opt/android-sdk/ndk   /usr/lib/android-sdk/ndk

If yours is somewhere else, say so:

    make NDKBIN=/path/to/ndk/toolchains/llvm/prebuilt/<host>/bin android

Building on the phone itself is easier. Termux's clang already targets Android,
so there's nothing to cross-compile:

    cc -O2 -o lanternet src/*.c

The C library is the only dependency. `src/oui_table.h` is the single file I
didn't write by hand: it's the vendor prefix list from Wireshark's manuf
database.

## Commands

    lanternet scan                  list hosts (vendor, name, OS hint, IPv6)
    lanternet listen [secs]         watch for names only, transmit nothing
    lanternet who <ip>              resolve one address
    lanternet name [<ip> <label>]   set or list saved names

    lanternet cut <ip>              cut one host for about three seconds
    lanternet resume <ip>           put one host back
    lanternet hold <ip> [bg]        keep one host cut
    lanternet holdall [bg]          keep every host cut, rescanning now and then
    lanternet auto [bg]             holdall, and re-arm if the link drops
    lanternet cutall                one burst across every host
    lanternet test <ip>             cut, wait, resume
    lanternet restore               undo everything in the state file
    lanternet stop | stopall        kill background runs

    lanternet sniffmac <mac> [s]    print frames arriving from one device
    lanternet sniffarp [s]          print ARP traffic

Everything except `stop` and `stopall` wants root. Flags can sit anywhere on
the line: `--v4`, `--v6`, `--all`, `--gw <ip>`, `--fake-mac`, `--dry`,
`--json`, `--guard <pid>`. Run it with no arguments for the same list.

## The app build

`make android-app` (or `make linux-app` to try it on the host) builds the same
tool for use inside an app, where there is no shell user to clean up after it.
Two differences:

- Nothing detaches. `bg` is refused on `hold`, `holdall`, `daemon` and `auto`,
  so the app can never leave behind a process it cannot see. The long-running
  modes stay in the foreground.
- `--guard <pid>` makes a long run watch a process and, if it disappears (the
  app was killed, swiped away, or reclaimed by the low-memory killer), repair
  the segment and exit. `SIGTERM` and `SIGINT` take the same path, so the app's
  stop button puts the network back on the way out. Nothing is poisoned before
  its state is recorded, so a guard exit can never leave a host cut.

The state file is the shared `lanternet.state`, so `restore` and `stopall` still
work from a shell. Point the app at its own copy of the binary,
`/data/local/tmp/lanternet-app`, so it does not overwrite the CLI one.

## Scan output

    192.168.1.1     f8:08:4f:1f:37:36
      Name    : MYMODEM (nbns)
      Vendor  : Sagemcom Broadband SAS
      OS      : unix
      IPv6    : fe80::fa08:4fff:fe1f:3736
      Flags   : gateway

    192.168.1.28    ec:9c:32:bd:d0:b5
      Name    : Android (mdns)
      Vendor  : Sichuan AI-Link Technology Co.
      OS      : unix

    192.168.1.46    36:c6:30:32:1f:fe
      Flags   : random-mac

Hosts come out sorted by IP, one block each, blank line between. Only fields
that have something in them are printed. `Name` carries the source it came from
in parentheses: `nbns`, `mdns`, `mdns-svc`, `ssdp`, `dhcp`, `lease`, `cache` or
`user`. `Flags` collects `gateway`, `cut`, `random-mac` and `this device`. Long
values wrap to the width of your terminal. `--json` gives the same data as
objects, if you want to feed it to something else.

## Where the names come from

The host list is three things merged: an ARP sweep of the subnet (the first
1024 addresses, or all of them with `--all`), the kernel neighbour table, and
`/proc/net/arp`. The gateway gets resolved even when it sits outside the swept
range. On top of that, local DHCP lease files if this device happens to be the
router.

Names are the messy part, so they come from wherever they can:

- ARP replies, for the MAC.
- The OUI table, for the vendor. Randomised MACs have none.
- NetBIOS node status queries. Only older or desktop machines answer these.
- mDNS: reverse lookups, plus browsing `_services._dns-sd._udp.local` for
  service names. This is where things like "Miele DGC7845" and "Living Room 1"
  come from.
- SSDP M-SEARCH, then fetching the responder's description XML for its
  `friendlyName`.
- Reverse DNS against the LAN resolver.
- Passive DHCP sniffing, reading option 12 (hostname) and option 60 (vendor
  class) off the wire.
- An ICMP TTL hint for a rough OS guess, and ICMPv6 echo to see if a host is
  reachable over IPv6.

Names get cached per MAC (`lanternet.cache`, in `/data/local/tmp` on Android
and `/tmp` on Linux), so a device only has to be caught once. That matters for
DHCP names in particular, since a device only announces its hostname when it
joins the network or renews its lease. A quiet device that's been on since
before you started the tool will show up with no name until it talks again.

## Limits

- Only works as far as layer 2 reaches. A different VLAN, a different subnet,
  or client isolation on the AP defeats it, the same as any ARP-based tool.
- It can't block cellular. A phone with mobile data on just falls back.
- On WiFi a packet socket can't see its own transmissions, so verification is
  done by watching what actually arrives back, not by sniffing what we sent.
- Names only appear if the device publishes one. Plenty don't.
- Built and tested against my own network and a rooted phone. It's a small tool
  for my own use, not a product.

It covers the cut and the discovery, and that's it. Defender mode, bandwidth
limits, a scheduler, traffic counters and a UI are all missing; if you want
those, NetCut is the reference implementation.

## License

AGPL-3.0-or-later, see `LICENSE`. Network use counts as conveying, so if you
run a modified version as a service you have to offer its source to the people
using it.

`src/oui_table.h` is generated from the Wireshark `manuf` database, which is
GPL-2.0-or-later and compatible with the above.
