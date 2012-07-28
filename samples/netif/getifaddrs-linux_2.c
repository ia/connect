
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/if_link.h>

int main(int argc, char *argv[]) {
  struct ifaddrs *ifaddr;
  int family, s;

  if (getifaddrs(&ifaddr) == -1) {
    perror("getifaddrs");
    exit(1);
  }

  struct ifaddrs *ifa = ifaddr;
  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr != NULL) {
      int family = ifa->ifa_addr->sa_family;
      if (family == AF_INET || family == AF_INET6) {
        char ip_addr[NI_MAXHOST];
        int s = getnameinfo(ifa->ifa_addr,
                            ((family == AF_INET) ? sizeof(struct sockaddr_in) :
                                                   sizeof(struct sockaddr_in6)),
                            ip_addr, sizeof(ip_addr), NULL, 0, NI_NUMERICHOST);
        if (s != 0) {
          printf("getnameinfo() failed: %s\n", gai_strerror(s));
          exit(1);
        } else {
          printf("%-7s: %s\n", ifa->ifa_name, ip_addr);
        }
      } else if (family == AF_PACKET) {
        struct rtnl_link_stats *stats = ifa->ifa_data;
        printf("%-7s:\n"
               "\ttx_packets = %12u, rx_packets = %12u\n"
               "\ttx_bytes   = %12u, rx_bytes   = %12u\n",
               ifa->ifa_name,
               stats->tx_packets, stats->rx_packets,
               stats->tx_bytes, stats->rx_bytes);
      } else {
        printf("%-7s: family=%d\n", ifa->ifa_name, family);
      }
    }
  }

  freeifaddrs(ifaddr);
  exit(0);
}

