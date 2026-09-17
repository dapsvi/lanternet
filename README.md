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

## Layout

    src/            the tool, one C file per subsystem (plus src/oui_table.h)
    Makefile        builds ./lanternet-linux and ./lanternet (Android arm64)
    android/        the Android app, a Gradle project with one module (app/)
    branding/       the mark as SVG, plus the scripts that generate the icons

## Build

    make             Linux binary  -> ./lanternet-linux
    make android     Android arm64 -> ./lanternet   (TUI stubbed; the NDK has no ncurses)
    make check       recompile with a much stricter warning set

The app is a normal Gradle project, and building it builds the tool first:
`preBuild` runs `make android` and copies the result into
`app/src/main/jniLibs/arm64-v8a/liblanternet.so`, so the APK can never ship a
stale binary.

    cd android
    ./gradlew assembleDebug     # -> app/build/outputs/apk/debug/app-debug.apk

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

Everything below is just a client of the server. To drive it from your own
code, the protocol is one JSON object per line over the Unix socket; see
"Talking to the socket" below.

    lanternet start                 run the server (root, foreground)
    lanternet tui                   live terminal UI
    lanternet status                server + live actions
    lanternet list [selector]       devices the scanner knows
    lanternet scan                  one sweep right now (the only active traffic by default)
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

`config` with no argument prints the tunables; `config interval_ms=5000` sets
one. Keys: `interval_ms`, `rate_pps`, `do_v4`, `do_v6`, `scan_paused`, and
booleans take `true` or `false`.

## What a scan does

One blow: a broadcast ARP request for every address on the subnet, the whole
range. Requests go out in batches of 64 with a 50 ms pause every 1024 so the
transmit ring can keep up, and a /24 takes about half a second. Anything the
ring refuses gets counted rather than lost silently; `status` shows it as
`drops`, which is what tells you a WiFi driver is eating your sweep. The
gateway is resolved too, even when it sits outside the swept range.

Every host already known then gets an ICMP echo, but not in one blocking burst:
the pings are spread over the server's ticks, so a cut is still being refreshed
while a scan runs. A host that answers an ARP or ICMP probe counts as `on`, and
`list` carries `on` plus `seen_s`, how long ago that was. An ARP reply is only
credited when it comes from the device's own MAC, so a layer 3 switch doing
proxy ARP cannot make a dead host look alive. After that the kernel ARP and
neighbour tables are merged in and the name work starts.

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
timer, pings every known host at the end of each pass, and sits quiet for 30
seconds between passes. It's off by default; a one-shot `scan` is the only
thing that talks unless you turn it on.

## Output

`list` prints a table, sorted by IP:

    IP              MAC                STATE   NAME                 TAGS
    192.168.1.1     f8:08:4f:1f:37:36  idle    MYMODEM              gateway
    192.168.1.28    ec:9c:32:bd:d0:b5  idle    Android
    192.168.1.46    36:c6:30:32:1f:fe  idle                         random-mac

`STATE` is `idle` or `held`. `TAGS` collects `gateway`, `cut`, `random-mac` and
`this device`. `--json` gives the same rows as objects, with `on` and `seen_s`
on them, if you want to feed them to something else.

`status` prints the interface, the gateway, the device count, the frame counter,
the dropped-frame counter and a line per live action.

## Stopping

Stopping an action just stops refreshing it. `resume` releases the hosts a
selector matches and stops any action still covering them, since the held set is
derived from the live actions on every tick: clearing the flags alone would be
undone 50 ms later. There are no repair packets, and
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

## Talking to the socket

The CLI and the TUI are just clients, so anything else can be one too. The
server listens on `$RUNDIR/lanternet.sock` (`/tmp` on Linux, `/data/local/tmp`
on Android), mode 0600, chowned to `$SUDO_UID` when you start it under `sudo`,
so whoever started it can talk to it without sudo again. One JSON object per
line in each direction: send a request, read one response, connection closes.
Open a fresh connection per request, up to 8 at once.

    {"v":1,"cmd":"status","sel":null,"state":null,"id":null,"value":null}

`sel` is a selector, `state` filters `list`, `id` is an action id for `stop`,
`value` is the argument for `setname` and `config`. Responses always use the
same envelope:

    {"v":1,"ok":true,"cmd":"...","err":null,"result":{...}}

On failure `ok` is `false`, `err` carries the reason and `result` is `{}`.

    status      {"iface","myip","gw","gwmac","hosts","frames","drops",
                 "scan_paused","actions":[{"id","sel","matched","age_s","interval_ms"}]}
    list        {"count":N,"hosts":[{"ip","mac","name","brand","state",
                 "last_ms","ttl","ip6","on","seen_s","tags":[...]}]}
    scan        {"hosts":N,"on":N,"frames":N}
    cut         {"action_id":N,"matched":N}
    stop        {"stopped":[id,...],"released":N}
    stopall     {"stopped":[id,...],"released":N}
    resume      {"released":N,"stopped":N}
    config      {"config":{"interval_ms","rate_pps","do_v4","do_v6",
                 "scan_paused","fake_mac"}}
    ping        {}
    scanpause   {}      scanresume {}      setname {}      shutdown {}

A scan by hand, and the reply:

    printf '{"v":1,"cmd":"scan"}\n' | nc -U /data/local/tmp/lanternet.sock

## The Android app

The app is a thin front end: it copies the arm64 binary out of its own
`jniLibs` to `/data/local/tmp/lanternet-app`, starts it through `su`, and does
everything else over the socket. It shows the device list with a live selector
filter and a host count on the tab, cuts and releases per device, and has a
settings tab for the tunables and a console tab for the raw output.

`branding/` holds the mark: `lanternet-mark.svg` (solid lantern with the wifi
knocked out), `-white.svg` for dark surfaces, `-outline.svg`, `-solid.svg` for
tiny sizes, plus `gen.py`, which draws them, and `make_icons.py`, which writes
the launcher icons into `android/`. Change a number in `gen.py`, rerun it, and
every icon follows.

## License

AGPL-3.0-or-later, see `LICENSE`. Network use counts as conveying, so if you
run a modified version as a service you have to offer its source to the people
using it.

`src/oui_table.h` is generated from the Wireshark `manuf` database, which is
GPL-2.0-or-later and compatible with the above.
