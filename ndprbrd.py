#!/usr/bin/python

# Copyright 2016 Google Inc.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# version 2 as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

import argparse
import logging
import logging.handlers
import netaddr
import pytun
import scapy.all
import socket
import subprocess
import time
import threading

parser = argparse.ArgumentParser()
parser.add_argument('--interface', required=True, action='append')
parser.add_argument('--prefix', required=True, type=netaddr.IPNetwork)
parser.add_argument('--expire', default=300, type=float)
# 100 is a good number, and doesn't clash with existing numbers in /etc/iproute2/rt_protos
parser.add_argument('--protocol', default=100, type=int)
parser.add_argument('--tun', default='ndprbrd')
args = parser.parse_args()

logger = logging.getLogger('MyLogger')
logger.addHandler(logging.handlers.SysLogHandler(address='/dev/log'))
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.INFO)

def find_pthread():
  do_nothing = lambda _1, _2: None
  import ctypes
  import ctypes.util
  libpthread_path = ctypes.util.find_library("pthread")
  if not libpthread_path:
    return do_nothing
  libpthread = ctypes.CDLL(libpthread_path)
  if not hasattr(libpthread, "pthread_setname_np"):
    return do_nothing
  pthread_setname_np = libpthread.pthread_setname_np
  pthread_setname_np.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
  pthread_setname_np.restype = ctypes.c_int
  return pthread_setname_np
pthread_setname_np = find_pthread()

routes = dict()
lock = threading.Lock()

def remember_route(addr, iface):
  lock.acquire()
  routes[addr] = (iface, time.time())
  lock.release()

def cleanup_routes():
  lock.acquire()
  past = time.time() - args.expire
  deleting = []
  for addr, (iface, t) in routes.iteritems():
    if t < past:
      deleting.append((addr, iface))
  for addr, iface in deleting:
    logger.info('ndprbrd: Removing {} from {}'.format(addr, iface))
    del routes[addr]
    subprocess.check_call(['ip', '-6', 'route', 'del', addr, 'dev', iface, 'protocol', str(args.protocol)])
  lock.release()

def replace_route(route, iface):
  subprocess.check_call(['ip', '-6', 'route', 'replace', str(route), 'dev', iface, 'protocol', str(args.protocol)])

class Watcher(threading.Thread):
  def __init__(self, iface):
    super(Watcher, self).__init__()
    self.iface = iface
  def run(self):
    pthread_setname_np(self.ident, 'iface:' + self.iface)
    s=socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
    s.setsockopt(socket.SOL_SOCKET, 25, self.iface + '\0')
    while True:
      raw_packet, addr = s.recvfrom(5120)
      if len(raw_packet) < 24:
        continue
      # type 136 - Neighbor Advertisement, RFC 4861
      if scapy.all.ICMPv6Unknown(raw_packet).type != 136:
        continue
      text_addr = scapy.all.ICMPv6ND_NA(raw_packet).tgt
      addr = netaddr.IPAddress(text_addr)
      if addr in args.prefix:
        logger.info('ndprbrd: Found {} on {}'.format(text_addr, self.iface))
        replace_route(addr, self.iface)
        remember_route(text_addr, self.iface)

def fill_routes():
  for iface in args.interface:
    for line in subprocess.check_output(['ip', '-6', 'route', 'show', 'protocol', str(args.protocol), 'dev', iface], universal_newlines=True).splitlines():
      text_addr = line.split(' ')[0]
      net = netaddr.IPNetwork(text_addr)
      if net.prefixlen == 128 and net in args.prefix:
        remember_route(text_addr, iface)

fill_routes()

for iface in args.interface:
  Watcher(iface).start()

tun = pytun.TunTapDevice(name=args.tun, flags=pytun.IFF_TAP)
tun.up()
replace_route(args.prefix, args.tun)
while True:
  buf = tun.read(tun.mtu)
  eth = scapy.all.Ether(buf[4:])
  logger.debug('ndprbrd: Received {}'.format(repr(eth)))
  if scapy.all.IPv6 not in eth:
    continue
  # Only allow Neighbor Solicitation on this tunnel
  if scapy.all.ICMPv6ND_NS not in eth:
    continue
  if netaddr.IPAddress(eth[scapy.all.ICMPv6ND_NS].tgt) not in args.prefix:
    continue
  logger.debug('ndprbrd: Sending Neighbor Solicitation about {}'.format(eth[scapy.all.ICMPv6ND_NS].tgt))
  for iface in args.interface:
    eth2 = eth.copy()
    eth2.src = scapy.all.get_if_hwaddr(iface)
    eth2[scapy.all.IPv6].src = next(addr for addr, num, intf in scapy.all.in6_getifaddr() if intf == iface and netaddr.IPAddress(addr) in netaddr.IPNetwork('fe80::/10'))
    if scapy.all.ICMPv6NDOptSrcLLAddr in eth2:
      eth2[scapy.all.ICMPv6NDOptSrcLLAddr].lladdr = eth2.src
    del eth2[scapy.all.ICMPv6ND_NS].cksum
    scapy.all.sendp(eth2, iface=iface, verbose=False)
