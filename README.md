# lanternet

Small C tool for working on a LAN. It maps what's on the network, and it can
cut a device off it.

It runs as one long-lived server plus thin clients. The server owns the raw
socket and all the state; the CLI and a curses TUI are just clients talking to
it over a Unix socket. Start the server once, as root, and then drive it from
anywhere on the box. When you start it with `sudo` it hands the control socket
to you, so the client and the TUI work as your normal user without a second
`sudo`.

The cut is ARP poisoning in both directions: I tell the victim that the gateway
lives at my MAC, and I tell the gateway that the victim lives at my MAC. Every
held host is re-poisoned on its own clock (2000 ms by default), and only the
hosts that are due get frames that tick, so a big network is a trickle instead
of a flood. The IPv6 half does the same thing with neighbour advertisements, so
a dual-stack device loses both paths.

Made for GNU/Linux and Android (root).

## Build

    make             Linux binary  -> ./lanternet-linux
    make android     Android arm64 -> ./lanternet   (TUI stubbed; the NDK has no ncurses)
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
so there's nothing to cross-compile. Install ncurses first if you want the TUI:

    pkg install ncurses
    cc -O2 -o lanternet src/*.c -lncursesw

Without ncurses anywhere to link, build with `-DNO_CURSES` and you get the whole
tool minus the TUI (that's what `make android` does, since the NDK ships no
ncurses). The C library is the only other dependency. `src/oui_table.h` is the
single file I didn't write by hand: it's the vendor prefix list from
Wireshark's manuf database.

## Running it

    sudo ./lanternet-linux start     # the server; foreground, needs root
    ./lanternet-linux scan           # from another shell, no sudo once it is up
    ./lanternet-linux list
    ./lanternet-linux tui            # or use the live UI

`start` runs in the foreground and stays up until you `shutdown` it or hit
Ctrl-C. While it is idle it holds one raw socket and transmits nothing. The
discovery sockets (mDNS, NetBIOS, ICMP, DHCP, SSDP, reverse DNS) are opened for
a scan and closed when it ends, so an idle server keeps no multicast
memberships and stays off the wire entirely.

## Commands

Everything below is just a client of the server. If you want to drive it from
your own code, the protocol is one JSON object per line over the Unix socket;
it's written up in `USAGE.md` under "Talking to the socket directly".

    lanternet start                 run the server (root, foreground)
    lanternet tui                   live terminal UI
    lanternet status                server + live actions
    lanternet list [selector]       devices the scanner knows
    lanternet scan [selector]       one sweep right now (the only active traffic by default)
    lanternet cut [selector]        start cutting matching devices (no selector = all)
    lanternet stop <id|selector>    stop action(s)
    lanternet stopall               stop everything
    lanternet resume [selector]     release matching devices
    lanternet scanpause|scanresume  background rediscovery on/off (off by default)
    lanternet setname <mac> <name>  give a device a permanent name
    lanternet config [key=val]      read or set tunables
    lanternet shutdown              stop the server

Flags can sit anywhere on the line: `--v4`, `--v6`, `--json`, `--dry`,
`--gw <ip>`, `--interval <ms>`, `--rate <pps>`, `--fake-mac [aa:bb:..]`,
`--guard <pid>`. Run it with no arguments for the same list.

Selectors match on ip, mac, name or tags, and combine with `&& || !`. Quote the
whole thing:

    lanternet cut 'random-mac && !tag:gateway'

`--guard <pid>` makes the server exit when that process is gone, which is what
an app or a wrapper wants so a killed run can't leave a cut behind.

## What a scan does

One blow: a broadcast ARP request for every address on the subnet. The gateway
gets resolved too, even when it sits outside the swept range. Every host that
is already known then gets an ICMP echo, so a device that stopped answering
turns up as `on:false` in `list`. Then the kernel ARP table and the neighbour
table are merged in, and the name work starts.

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

Names get cached per MAC (`lanternet.cache`, in `/tmp` on Linux and
`/data/local/tmp` on Android), so a device only has to be caught once. That
matters for DHCP names in particular, since a device only announces its
hostname when it joins the network or renews its lease. A quiet device that's
been up since before you started the tool shows no name until it talks again.

`scanpause` and `scanresume` toggle the background scanner, which sweeps on a
timer and sits quiet for 30 seconds between passes. It's off by default; a
one-shot `scan` is the only thing that talks unless you turn it on.

## Output

`list` prints a table, sorted by IP:

    IP              MAC                STATE   NAME                 TAGS
    192.168.1.1     f8:08:4f:1f:37:36  idle    MYMODEM              gateway
    192.168.1.28    ec:9c:32:bd:d0:b5  idle    Android
    192.168.1.46    36:c6:30:32:1f:fe  idle                         random-mac

`STATE` is `idle`, `held` or `restoring`. `TAGS` collects `gateway`, `cut`,
`random-mac` and `this device`. `--json` gives the same rows as objects, if you
want to feed them to something else.

`status` prints the interface, the gateway, the device count, the frame counter
and a line per live action.

## Stopping

Stopping an action just stops refreshing it. There are no repair packets, and
nothing the tool sends ever carries the router's MAC as its Ethernet source.
A poison only holds while it is being refreshed, so a released host falls out
of the victims' ARP caches by itself within a minute. The same goes for
`shutdown` and Ctrl-C, and the server repairs nothing when it starts either.
The reason for all of this: putting a poisoned host back means sending it an
ARP reply that says "the gateway is at the gateway's MAC", and that frame has
to carry the router's MAC as its source. Routers with any kind of attack
protection read that as gateway spoofing and react badly, so we simply don't
send it and let the entry expire instead.

## Limits

- Only works as far as layer 2 reaches. A different VLAN, a different subnet,
  or client isolation on the AP defeats it, the same as any ARP-based tool.
- Networks with ARP/ND inspection (dynamic ARP inspection, RA guard) drop the
  poison on the floor, and some routers flag the attempt. On those it just
  won't work, and you may end up in a log.
- It can't block cellular. A phone with mobile data on just falls back.
- On WiFi a packet socket can't see its own transmissions, so verification is
  done by watching what actually arrives back, not by sniffing what we sent.
- Names only appear if the device publishes one. Plenty don't.
- Built and tested against my own network and a rooted phone. It's a small tool
  for my own use, not a product.

It covers the cut and the discovery, and that's it. Defender mode, bandwidth
limits, a scheduler, traffic counters and a nicer UI are all missing; if you
want those, NetCut is the reference implementation.

## License

AGPL-3.0-or-later, see `LICENSE`. Network use counts as conveying, so if you
run a modified version as a service you have to offer its source to the people
using it.

`src/oui_table.h` is generated from the Wireshark `manuf` database, which is
GPL-2.0-or-later and compatible with the above.
