[![Build Status](https://img.shields.io/travis/google/ndprbrd/master.svg)](https://travis-ci.org/google/ndprbrd)

# ndprbrd - NDP Routing Bridge Daemon.

Disclaimer: This is not an official Google product.

This daemon has a very specific purpose: to give the same IPv6 prefix /64 to
several network interfaces using radvd without creating L2 bridge and without
need to configure DHCPv6. It's designed to be used together with
[ndppd](https://github.com/DanielAdolfsson/ndppd) for case if ISP gives
single /64 without delegating a bigger prefix to your router.

## Deprecation notice

On 2017-08-07 this functionality [was
merged](https://github.com/DanielAdolfsson/ndppd/pull/30) into ndppd itself.
However, there are several caveats:

*   If ndppd crashes for whatever reason, routes which it adds are never
    deleted. If this risk is unacceptable for you, use ndprbrd until [this
    issue](https://github.com/DanielAdolfsson/ndppd/issues/32) is fixed.
*   There was no new release of ndppd yet, so your favorite distro may have a
    version which doesn't support it. In that case you need to either still use
    ndprbrd, or build ndppd from git master.

An example ndppd config with this functionality enabled:

```
proxy eth0 {
  autowire yes
  rule 2001:db8:1:2::/64 {
    iface eth1
  }
  rule 2001:db8:1:2::/64 {
    iface eth2
  }
}
proxy eth1 {
  autowire yes
  rule 2001:db8:1:2::/64 {
    iface eth0
  }
  rule 2001:db8:1:2::/64 {
    iface eth2
  }
}
proxy eth2 {
  autowire yes
  rule 2001:db8:1:2::/64 {
    iface eth0
  }
  rule 2001:db8:1:2::/64 {
    iface eth1
  }
}
```

If new ndppd is enough for you, you can stop reading now.

# How to use ndprbrd

Below are 2 sample setups - the simple one which doesn't need ndprbrd, and the
more complicated one which makes use of it. The simple setup sets the base for
the more complicated one.

## Setup which does not need ndprbrd

```
+-------------------+
|        ISP        |
|  radvd announces  |
| 2001:db8:1:2::/64 |
+---------+---------+
          |
          |
          | eth0
          | addr 2001:db8:1:2::42
          | default route via link-local address
          | ndppd answers to NDP solicitations, so ISP thinks that the whole 2001:db8:1:2::/64 is here
   +------+------+
   |  My router  |
   +------+------+
          | eth1
          | radvd announces 2001:db8:1:2::/64
          | route to 2001:db8:1:2::/64
          |
          |
       +--+--+
       | LAN |
       +-----+
```

*   A packet comes from internet to 2001:db8:1:2::33
*   ISP sends NDP neigbor solicitation to the wire
*   ndppd sees it, and replies to it
    *   depending on whether `auto` or `static` is used, ndppd behaves slightly
        differently, but I don't want to go to such details. Both modes work.
*   Router sends solicitation to LAN, gets response (neighbor advertisement),
    sends packets to there, and everyone is happy.

## Setup with makes use of ndprbrd

```
+-------------------+
|        ISP        |
|  radvd announces  |
| 2001:db8:1:2::/64 |
+---------+---------+
          |
          |
          | eth0
          | addr 2001:db8:1:2::42
          | default route via link-local address
          | ndppd answers to NDP solicitations, so ISP thinks that the whole 2001:db8:1:2::/64 is here
   +------+------+
   |             |
   |             | eth2                                 +-------+
   |  My router  +--------------------------------------+ LAN-2 |
   |             | radvd announces 2001:db8:1:2::/64    +-------+
   |             |
   +------+------+
          | eth1
          | radvd announces 2001:db8:1:2::/64
          |
          |
      +---+---+
      | LAN-1 |
      +-------+
```

A packet already reached Router due to the same setup of eth0 as before, now it
tries to reach an address 2001:db8:1:2::33. But which of two LANs contain this
address? They both use the same prefix! Having route 2001:db8:1:2::/64 on both
eth1 and eth2 won't work, as such routes will collide, and kernel will send
packets to only one of interfaces.

This is where ndprbrd comes to rescue. It has 2 modes, using TAP interface (the
recommended mode), and not using it.

```
                       | eth0
                 +-----+-----+
+-------+   eth1 |           | eth2   +-------+
| LAN-1 +--------+ My router +--------+ LAN-2 |
+-------+     ^  |           |     ^  +-------+
              |  +-----+-----+     |
              |        | ndprbrd0  |
              |        | route to 2001:db8:1:2::/64
              |        | accepts NDP solicitations only, and sends them to both LANs
              |        |           |
              +--------+-----------+
```

When Router tries to send a packet, it sends neighbor solicitation to ndprbrd0,
and ndprbrd resends it to all interfaces which it's configured to use. Let's
say LAN-1 replies with neighbor advertisement. Then ndprbrd sees it, and adds a
static route to the advertised address 2001:db8:1:2::33 to interface eth1. From
this point all packets to that address will go directly to eth1, and not to
eth2, and not even to ndprbrd0.

If at some point later advertisements about 2001:db8:1:2::33 stopped coming from
eth1, the static route is removed after a timeout (10 minutes by default). Then,
if a new packet comes to that address, all LANs will be used to discover it
again.

Only absence of traffic will trigger such timeout, because with traffic the
neighbor solicitations are still sent from time to time. The solicitation will
go directly to eth1 because of the static route, the machine will reply, and
ndprbrd will see it and reset the timer.

```
                                   | eth0
route to 2001:db8:1:2:33/128       |
route to 2001:db8:1:2:77/128 +-----+-----+ route to 2001:db8:1:2::55/128
        +-------+       eth1 |           | eth2       +-------+
        | LAN-1 +------------+ My router +------------+ LAN-2 |
        +-------+         ^  |           |      ^     +-------+
                          |  +-----+-----+      |
                          |        | ndprbrd0   |
                          |        | route to 2001:db8:1:2::/64
                          |        | accepts NDP solicitations only, and sends them to both LANs
                          |        |            |
                          +--------+------------+
```

There is one more missing step: what happens when a machine in LAN-1 tries to
send something to LAN-2? The answer is ndppd again: instead of listening only on
eth0 ndppd should listen also on eth1 and eth2.

Note about firewall setup: forwarding from eth0 to ndprbrd0 should be accepted.
Otherwise, kernel won't generate NDP solicitations to ndprbrd0. (TODO: this
statement is true for `static` configuration of ndppd on eth0. Probably `auto`
doesn't require this, but I didn't check)

### The mode without TAP interface (not recommended)

If Linux is compiled without TUN/TAP interface support, another mode is
available. In this mode, ndprbrd every second switches the route to
2001:db8:1:2::/64 from one interface to another. So when the neighbor
solicitation is sent, there is a chance that it's sent to the correct LAN, in
which case ndprbrd will see the neighbor advertisement, and add the route for
that address.

Note that when an address is discovered in some LAN, due to the timeout
mechanism described above, that address will continue working until it
disappears from that LAN for 10 minutes. However, several first packets are
likely to be dropped. In TAP mode they are still likely to be dropped, but
number of first packets dropped is smaller in TAP mode.

## Usage

`./ndprbrd --interface=eth1 --interface=eth2 --prefix=2001:db8:1:2::/64`

To change name of TAP interface, use `--tun=foo`. To use the mode without TAP
interface, use `--pendulum`.

Sample config of ndppd:

```
proxy eth0 {
  rule 2001:db8:1:2::/64 {
    auto
  }
}
proxy eth1 {
  rule 2001:db8:1:2::/64 {
    auto
  }
}
proxy eth2 {
  rule 2001:db8:1:2::/64 {
    auto
  }
}
```

Note that eth0 (interface connected to ISP) is in ndppd, but not in ndprbrd.

Also note that routers don't usually accept RA themselves, so you might need to
specify the default route yourself (or try to set `accept_ra` to 2).

## Dependencies

*   Linux
*   Compiler with C++11 support:
    *   GCC 4.9+
    *   Clang 3.5 with libstdc++ 4.9
    *   Earlier Clang and Clang with libc++ are not tested

## Alternatives

*   Switch ISP to one that gives more than /64 :-)
*   Give different parts of /64 to LAN-1 and LAN-2, but that breaks SLAAC, so
    *    Configure a static address for every host,
    *    Or use DHCPv6
*   Bridge all networks together, which means that IPv4 will also be in a
    single subnet
