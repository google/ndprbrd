// Copyright 2016 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <array>
#include <functional>
#include <sstream>
#include <iostream>
#include <chrono>
#include <vector>
#include <unordered_map>
#include <queue>
#include <list>
#include <memory>
#include <cstdlib>
#include <cstring>
#include <cassert>

#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <ifaddrs.h>
#include <sys/epoll.h>

#include "third_party/cxxopts/include/cxxopts.hpp"
#include "third_party/cpp-subprocess/include/subprocess.hpp"

class EventLoop {
 public:
  EventLoop() : ep_(::epoll_create(20)) {
    if (ep_ == -1) {
      std::cerr << "Error creating epoll: " << std::strerror(errno)
                << std::endl;
      std::exit(1);
    }
  }

  void addReadFd(int fd, std::function<void(int fd)> callback) {
    epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.fd = fd;
    if (::epoll_ctl(ep_, EPOLL_CTL_ADD, fd, &ev)) {
      std::cerr << "Error adding socket to epoll: " << std::strerror(errno)
                << std::endl;
      std::exit(1);
    }
    sockets_[fd] = std::move(callback);
  }

  void addTimer(std::chrono::milliseconds period,
                std::function<void()> callback) {
    // The time will skew over time, but preciseness doesn't matter here
    addSingleShot(std::chrono::steady_clock::now() + period, [=]() {
      callback();
      addTimer(period, std::move(callback));
    });
  }

  void run() {
    constexpr int kLen = 10;
    epoll_event ev[kLen]{};
    while (true) {
      std::chrono::milliseconds millis = std::chrono::seconds(30);
      if (!timers_.empty()) {
        millis = std::chrono::duration_cast<std::chrono::milliseconds>(
            timers_.top().when - std::chrono::steady_clock::now());
      }
      if (millis.count() >= 0) {
        int n = ::epoll_wait(ep_, ev, kLen, millis.count());
        if (n == -1) continue;
        for (int i = 0; i < n; ++i) {
          sockets_[ev[i].data.fd](ev[i].data.fd);
        }
      }
      auto now = std::chrono::steady_clock::now();
      // This scary condition ensures no busy loop of calling epoll_wait with
      // zero timeout within single millisecond
      while (!timers_.empty() &&
             std::chrono::duration_cast<std::chrono::milliseconds>(
                 timers_.top().when -
                 now).count() <= 0) {
        Shot shot = timers_.top();
        timers_.pop();
        shot.callback();
      }
    }
  }

 private:
  void addSingleShot(std::chrono::steady_clock::time_point when,
                     std::function<void()> callback) {
    timers_.push(Shot{when, std::move(callback)});
  }

  struct Shot {
    std::chrono::steady_clock::time_point when;
    std::function<void()> callback;

    bool operator<(const Shot& other) const { return when > other.when; }
  };

  const int ep_;
  std::priority_queue<Shot> timers_;
  std::unordered_map<int /* fd */, std::function<void(int fd)>> sockets_;
};

bool ParseTextAddress(const std::string& addr, char* output, int len) {
  assert(len <= 16);
  addrinfo hints{};
  hints.ai_family = AF_INET6;
  hints.ai_flags = AI_NUMERICHOST;
  addrinfo *result;
  if (::getaddrinfo(addr.c_str(), nullptr, &hints, &result) != 0) {
    return false;
  }
  if (result->ai_addr->sa_family != AF_INET6) {
    ::freeaddrinfo(result);
    return false;
  }
  std::memcpy(
      output,
      reinterpret_cast<sockaddr_in6*>(result->ai_addr)->sin6_addr.s6_addr, len);
  ::freeaddrinfo(result);
  return true;
}

template<typename Char>
std::string ParseBinAddress(const Char* addr, int len) {
  assert(len == 16);
  sockaddr_in6 ad{};
  ad.sin6_family = AF_INET6;
  std::memcpy(ad.sin6_addr.s6_addr, addr, len);
  char buf[INET6_ADDRSTRLEN]{};
  ::getnameinfo(reinterpret_cast<sockaddr *>(&ad), sizeof ad, buf, sizeof buf,
                nullptr, 0, NI_NUMERICHOST);
  return buf;
}

class PrefixList {
 public:
  explicit PrefixList(const std::vector<std::string>& list) {
    if (list.empty()) {
      std::cerr << "Error: --prefix is required." << std::endl;
      std::exit(1);
    }
    for (const std::string& prefix : list) {
      std::istringstream inbuf(prefix);
      std::string addr;
      std::getline(inbuf, addr, '/');
      int suffix;
      inbuf >> suffix;
      if (suffix != 64) {
        std::cerr << "Error: prefix should be /64" << std::endl;
        std::exit(1);
      }
      std::array<char, 8> buf;
      if (!ParseTextAddress(addr, buf.data(), 8)) {
        std::cerr << "Error: can't parse prefix" << std::endl;
        std::exit(1);
      }
      prefixes_.push_back(buf);
    }
  }
  template<typename Char>
  bool contains(const Char* bin_addr) const {
    for (const auto& prefix : prefixes_) {
      if (std::memcmp(prefix.data(), bin_addr, 8) == 0) return true;
    }
    return false;
  }

 private:
  std::vector<std::array<char, 8>> prefixes_;
};

class RouteTable {
 public:
  explicit RouteTable(const std::string& proto, std::chrono::seconds ttl)
      : proto_(proto), ttl_(ttl) {}
  void learn(const std::string& addr, const std::string& iface) {
    auto it = routes_.find(addr);
    if (it != routes_.end() && it->second.first != iface) {
      delSystem(addr, it->second.first);
    }
    routes_[addr] =
        std::make_pair(iface, std::chrono::steady_clock::now() + ttl_);
  }
  void cleanup() {
    // TODO use min heap
    auto now = std::chrono::steady_clock::now();
    for (auto it = routes_.begin(); it != routes_.end();) {
      if (it->second.second < now) {
        delSystem(it->first, it->second.first);
        it = routes_.erase(it);
      } else {
        ++it;
      }
    }
  }
  void replaceSystem(const std::string& addr, const std::string& iface) {
    subprocess::popen pr("ip", {"-6", "route", "replace", addr, "dev", iface,
                                "protocol", proto_});
    pr.wait();
  }

 private:
  void delSystem(const std::string& addr, const std::string& iface) {
    std::cout << "deleting " << addr << " from " << iface << std::endl;
    subprocess::popen pr(
        "ip", {"-6", "route", "del", addr, "dev", iface, "protocol", proto_});
    pr.wait();
  }

  std::unordered_map<
      std::string,
      std::pair<std::string /* iface */,
                std::chrono::steady_clock::time_point /* expiration time */>>
      routes_;
  std::string proto_;
  std::chrono::seconds ttl_;
};

class SocketWatcher {
 public:
  SocketWatcher(const std::string& iface, const PrefixList* prefixes,
                RouteTable* routes, EventLoop* loop)
      : iface_(iface), prefixes_(prefixes), routes_(routes) {
    int sock = ::socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (sock == -1) {
      int e = errno;
      std::cerr << "Error: can't create ICMPv6 socket: " << std::strerror(e)
                << std::endl;
      std::exit(1);
    }
    if (::setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, iface.c_str(),
                     iface.length() + 1) == -1) {
      int e = errno;
      std::cerr << "Error: can't bind socket to " << iface << ": "
                << std::strerror(e) << std::endl;
      std::exit(1);
    }
    if (::fcntl(sock, F_SETFL, ::fcntl(sock, F_GETFL) | O_NONBLOCK) == -1) {
      int e = errno;
      std::cerr << "Error: can't make socket non-blocking: " << std::strerror(e)
                << std::endl;
      std::exit(1);
    }
    loop->addReadFd(sock, [this](int sock) { readFrom(sock); });
  }

 private:
  void readFrom(int sock) {
    char buf[24];
    sockaddr_storage addr{};
    socklen_t addrLen = sizeof addr;
    ssize_t len = ::recvfrom(sock, buf, sizeof buf, /* flags = */ 0,
                             reinterpret_cast<sockaddr*>(&addr), &addrLen);
    if (len < 24) return;
    if (buf[0] != '\x88') return;  // Neighbor Advertisement, RFC 4861
    if (!prefixes_->contains(buf + 8)) return;
    std::string remoteAddr = ParseBinAddress(buf + 8, 16);
    routes_->learn(remoteAddr, iface_);
    routes_->replaceSystem(remoteAddr, iface_);
  }
  const std::string iface_;
  const PrefixList* prefixes_;
  RouteTable* routes_;
};

class LinkLocal {
 public:
  const in6_addr* get(const std::string& iface) {
    rebuild();
    auto it = cache_.find(iface);
    if (it == cache_.end()) return nullptr;
    return &it->second;
  }

 private:
  void rebuild() {
    if (std::chrono::steady_clock::now() < expire_) return;
    cache_.clear();
    ifaddrs* ifa;
    if (::getifaddrs(&ifa)) {
      std::cerr << "getifaddrs: " << std::strerror(errno) << std::endl;
      return;
    }
    for (ifaddrs* i = ifa; i; i = i->ifa_next) {
      if (!i->ifa_addr) continue;
      if (i->ifa_addr->sa_family != AF_INET6) continue;
      in6_addr* ad = &reinterpret_cast<sockaddr_in6*>(i->ifa_addr)->sin6_addr;
      // fe80::/10
      if (ad->s6_addr[0] == 0xFE && (ad->s6_addr[1] & 0xC0) == 0x80) {
        cache_[i->ifa_name] = *ad;
      }
    }
    ::freeifaddrs(ifa);
    expire_ = std::chrono::steady_clock::now() + std::chrono::minutes(1);
  }

  std::unordered_map<std::string, in6_addr> cache_;
  std::chrono::steady_clock::time_point expire_;
};

class Tunnel {
 public:
  Tunnel(const std::string& name, std::vector<std::string> interfaces,
         const PrefixList* prefixes, EventLoop* loop)
      : interfaces_(std::move(interfaces)), prefixes_(prefixes) {
    int tap = ::open("/dev/net/tun", O_RDWR);
    if (tap == -1) {
      std::cerr << "Error: can't create TAP interface" << std::endl;
      std::exit(1);
    }
    struct ifreq ifr {};
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    std::strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ);
    if (::ioctl(tap, TUNSETIFF, &ifr) == -1) {
      int e = errno;
      std::cerr << "Error: can't configure TAP interface: " << std::strerror(e)
                << std::endl;
      std::exit(1);
    }
    name_.assign(ifr.ifr_name, ::strnlen(ifr.ifr_name, IFNAMSIZ));
    if (::fcntl(tap, F_SETFL, ::fcntl(tap, F_GETFL) | O_NONBLOCK) == -1) {
      int e = errno;
      std::cerr << "Error: can't make TAP interface non-blocking: "
                << std::strerror(e) << std::endl;
      std::exit(1);
    }
    sock_ = ::socket(AF_PACKET, SOCK_RAW, ETH_P_IPV6);
    if (sock_ == -1) {
      int e = errno;
      std::cerr << "Error: can't create raw socket: " << std::strerror(e)
                << std::endl;
      std::exit(1);
    }
    // SIOCGIFFLAGS wants a socket. It doesn't matter which exact one.
    if (::ioctl(sock_, SIOCGIFFLAGS, &ifr) == -1) {
      int e = errno;
      std::cerr << "Error: can't get TAP flags: " << std::strerror(e)
                << std::endl;
      std::exit(1);
    }
    ifr.ifr_flags |= IFF_UP;
    if (::ioctl(sock_, SIOCSIFFLAGS, &ifr) == -1) {
      int e = errno;
      std::cerr << "Error: can't bring TAP interface up: " << std::strerror(e)
                << std::endl;
      std::exit(1);
    }
    loop->addReadFd(tap, [this](int tap) { readFrom(tap); });
  }

  std::string name() const { return name_; }

 private:
  void readFrom(int tap) {
    char buf[86];
    ssize_t len = ::read(tap, buf, sizeof buf);
    if (len < 78) return;
    // Ethertype: IPv6
    if (buf[12] != '\x86' || buf[13] != '\xDD') return;
    // IPv6 Next Header: ICMPv6
    if (buf[20] != '\x3A') return;
    // ICMPv6 Type: Neighbor Solicitation
    if (buf[54] != '\x87') return;
    if (!prefixes_->contains(/* remote addr */buf + 62)) return;
    sockaddr_ll ll{};
    ll.sll_family = AF_PACKET;
    ll.sll_protocol = ETH_P_IPV6;
    ll.sll_halen = 6;
    std::memcpy(ll.sll_addr, buf, ETH_ALEN);
    for (const std::string& iface : interfaces_) {
      sendTo(iface, &ll, buf, len);
    }
  }

  void sendTo(const std::string& iface, sockaddr_ll* ll, char* buf,
              ssize_t len) {
    ifreq ifr{};
    std::strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ);
    if (::ioctl(sock_, SIOCGIFINDEX, &ifr) == -1) return;
    ll->sll_ifindex = ifr.ifr_ifindex;
    if (::ioctl(sock_, SIOCGIFHWADDR, &ifr) == -1) return;
    // Source in Ethernet header
    std::memcpy(buf + 6, ifr.ifr_hwaddr.sa_data, 6);
    if (len == 86) {
      // Source link-layer address in Options of ICMPv6
      std::memcpy(buf + 80, ifr.ifr_hwaddr.sa_data, 6);
    }

    const in6_addr* new_addr = linkLocal_.get(iface);
    if (!new_addr) return;
    std::memcpy(buf + 22, new_addr->s6_addr, 16);
    uint32_t sum = htons(0x3A);
    *reinterpret_cast<uint16_t*>(buf + 56) = 0;
    sum += *reinterpret_cast<uint16_t*>(buf + 18); // length
    for (int i = 22; i < len; i += 2) {
      sum += *reinterpret_cast<uint16_t*>(buf + i);
    }
    while (sum >> 16) sum = (sum >> 16) + (sum & 0xffff);
    *reinterpret_cast<uint16_t*>(buf + 56) = ~static_cast<uint16_t>(sum);
    ::sendto(sock_, buf, len, /* flags = */ 0, reinterpret_cast<sockaddr*>(ll),
             sizeof *ll);
  }

  int sock_;
  const std::vector<std::string> interfaces_;
  const PrefixList* prefixes_;
  std::string name_;
  LinkLocal linkLocal_;
};

int main(int argc, char** argv) {
  cxxopts::Options options(argv[0], "NDP Routing Bridge Daemon");
  std::vector<std::string> interfaces;
  std::vector<std::string> prefixesStr;
  int expire{};
  int proto{};
  bool pendulumOpt{};
  std::string tun;
  options.add_options()
      // clang-format off
      ("help", "Print this help")
      ("interface", "LAN interfaces where hosts are discovered (multiple allowed)", cxxopts::value(interfaces), "IFACE")
      ("prefix", "Subnets /64 which should be routed by ndprbrd (multiple allowed)", cxxopts::value(prefixesStr), "PREFIX")
      ("expire", "How long should discovered routes stay when not used, in seconds", cxxopts::value(expire)->default_value("600"), "N")
      ("protocol", "Protocol num for routing table, as known by kernel", cxxopts::value(proto)->default_value("100"), "N")
      ("pendulum", "(not recommended) Rapidly switch default route between LAN interfaces instead of creating TAP interface", cxxopts::value(pendulumOpt))
      ("tun", "Name of TAP interface to create", cxxopts::value(tun)->default_value("ndprbrd%d"), "IFACE");
  // clang-format on
  auto printHelp = [&]() {
    std::cout << options.help({""}) << "\nExample:\n  " << argv[0]
              << " --interface=eth1 --interface=eth2 --prefix=2001:db8:1:2::/64"
              << std::endl;
  };
  try {
    options.parse(argc, argv);
  } catch (const cxxopts::OptionException& e) {
    std::cerr << "Error: " << e.what() << std::endl;
    printHelp();
    std::exit(1);
  }
  if (options.count("help")) {
    printHelp();
    std::exit(0);
  }
  if (interfaces.empty()) {
    std::cerr << "Error: --interface is required." << std::endl;
    printHelp();
    std::exit(1);
  }
  PrefixList prefixes(prefixesStr);

  EventLoop loop;
  RouteTable routes(std::to_string(proto), std::chrono::seconds(expire));
  std::list<SocketWatcher> watchers;

  for (const std::string& iface : interfaces) {
    // Fill the table with existing routes
    subprocess::popen pr("ip", {"-6", "route", "show", "dev", iface, "protocol",
                                std::to_string(proto)});
    pr.wait();
    std::string line;
    while (std::getline(pr.stdout(), line)) {
      std::istringstream inbuf(line);
      std::string address;
      std::getline(inbuf, address, ' ');
      if (address.empty()) continue;
      char addr[8]{};
      if (!ParseTextAddress(address, addr, 8)) continue;
      if (prefixes.contains(addr)) {
        routes.learn(address, iface);
      }
    }
    // Start watching the interface
    watchers.emplace_back(iface, &prefixes, &routes, &loop);
  }

  loop.addTimer(std::chrono::seconds(5), [&]() { routes.cleanup(); });
  int pendulumCurrent = 0;
  std::unique_ptr<Tunnel> tunnel;

  if (pendulumOpt) {
    loop.addTimer(std::chrono::seconds(1), [&]() {
      int& current = pendulumCurrent;
      for (const std::string& prefix : prefixesStr) {
        routes.replaceSystem(prefix, interfaces[current]);
      }
      current = (current + 1) % interfaces.size();
    });
  } else {
    tunnel.reset(new Tunnel(tun, std::move(interfaces), &prefixes, &loop));
    for (const std::string& prefix : prefixesStr) {
      routes.replaceSystem(prefix, tunnel->name());
    }
  }

  loop.run();
  return 0;
}
