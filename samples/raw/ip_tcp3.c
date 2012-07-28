#include <arpa/inet.h>
#include <ctype.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

struct PseudoHdr
{
  unsigned long  saddr;
  unsigned long  daddr;
  char           reserved;
  unsigned char  protocol;
  unsigned short length;
};

#define PSEUDO sizeof(struct pseudohdr)
#define TCPHDR sizeof(struct tcphdr)
#define Z_NL   4294967295

unsigned short c_sum(unsigned short* data, int nbytes)
{
  unsigned long sum = 0;

  for (; nbytes > 1; nbytes -= 2)
  {
    sum += *data++;
  }

  if (nbytes == 1)
  {
    sum += *(unsigned char*) data;
  }

  sum  = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);

  return ~sum;
}

int fillAddress(int domain, const char* address, unsigned short port, struct sockaddr_in* sin);

unsigned char* buildTCPDatagram(struct sockaddr_in* src_sin, struct sockaddr_in* dst_sin, const unsigned char* msg, unsigned int msgSize);

unsigned int buildPseudoHdrBuffer(unsigned int src_addr, unsigned int dst_addr, unsigned int protocol,
                                  const unsigned char* hdrData, unsigned int hdrBytes,
                                  const unsigned char* msgData, unsigned int msgBytes,
                                  unsigned short** buffer);

int main(int argc, char** argv)
{
  const char*          dest_ip   = (argc > 1 ? argv[1] : "127.0.0.1");   // destination IP
  const unsigned short dest_port = (argc > 2 ? atoi(argv[1]) : 80);      // destination port

  srand(time(0));

  // root-privileges needed for the following operation
  int s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);

  if (s <= 0)
  {
    perror("[open_sockraw] socket()");
    return 1;
  }

  int enable = 1;
  if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable)) < 0)
  {
    printf("Error: setsockopt() - Cannot set HDRINCL:\n");
    return 1;
  }

  // We no longer need root privileges
  setuid(getuid());

  // build up out source and destination sock addresses
  struct sockaddr_in src_sin;
  struct sockaddr_in dst_sin;

  fillAddress(PF_INET, "127.0.0.1", 1234, &src_sin);
  fillAddress(PF_INET, dest_ip, dest_port, &dst_sin);


  // build our TCP datagram
  char*          msg          = "Hello World";
  unsigned char* datagram     = buildTCPDatagram(&src_sin, &dst_sin, (unsigned char*) msg, strlen(msg));
  unsigned int   datagramSize = sizeof(struct ip) + sizeof(struct tcphdr) + strlen(msg);

//  int i;
//  for (i = 0; i < 3; ++i)
//  {
    if (sendto(s, datagram, datagramSize, 0, (struct sockaddr*) &dst_sin, sizeof(dst_sin)) < 0)
    {
      printf("Error with sendto() -- %s (%d)\n", strerror(errno), errno);
//      break;
    }
//  }
  free(datagram);

  return 0;
}  


int fillAddress(int domain, const char* address, unsigned short port, struct sockaddr_in* sin)
{
  if (!address)
  {
    memset(sin, 0, sizeof(struct sockaddr_in));

    sin->sin_family      = domain;
    sin->sin_addr.s_addr = htonl(INADDR_ANY);
    sin->sin_port        = htons(port);
  }
  else
  {
    struct addrinfo  hints;
    struct addrinfo* host_info = 0;

    memset(&hints, 0, sizeof(hints));

    hints.ai_family = domain;

    if (getaddrinfo(address, 0, &hints, &host_info) != 0  ||
        !host_info || !host_info->ai_addr || host_info->ai_family != domain)
    {
      if (host_info) freeaddrinfo(host_info);
      return -1;
    }

    memcpy(sin, host_info->ai_addr, sizeof(struct sockaddr_in));
    sin->sin_port = htons(port);

    freeaddrinfo(host_info);
  }

  return 0;
}


unsigned char* buildTCPDatagram(struct sockaddr_in* src_sin, struct sockaddr_in* dst_sin, const unsigned char* msg, unsigned int msgSize)
{
  const int      ip_len   = sizeof(struct ip) + sizeof(struct tcphdr) + msgSize;
  unsigned char* datagram = calloc(1, ip_len);

  if (!datagram) return 0;

  // setup useful pointers to locations within the datagram
  struct ip*     iph  = (struct ip*) datagram;
  struct tcphdr* tcph = (struct tcphdr*)(datagram + sizeof(struct ip));
  unsigned char* data = datagram + sizeof(struct ip) + sizeof(struct tcphdr);

  // build IP header
  iph->ip_hl         = sizeof(struct ip) >> 2;
  iph->ip_v          = 4;
  iph->ip_tos        = 0;
  iph->ip_len        = htons(ip_len);
  iph->ip_id         = htons((int)(rand()/(((double)RAND_MAX + 1)/14095)));
  iph->ip_off        = 0;
  iph->ip_ttl        = 64;
  iph->ip_p          = IPPROTO_TCP;
  iph->ip_sum        = 0;
  iph->ip_src.s_addr = src_sin->sin_addr.s_addr;
  iph->ip_dst.s_addr = dst_sin->sin_addr.s_addr;

  // now we compute the checksum for the IP header (albeit this is optional)
  iph->ip_sum = c_sum((unsigned short*) iph, sizeof(struct ip));

  // build TCP header
  tcph->source  = htons(src_sin->sin_port);
  tcph->dest    = htons(dst_sin->sin_port);
  tcph->seq     = htonl((int)(rand()/(((double)RAND_MAX + 1)/Z_NL)));
  tcph->ack_seq = htonl(0);
  tcph->res1    = 0;
  tcph->doff    = sizeof(struct tcphdr) >> 2;
  tcph->fin     = 1;
  tcph->syn     = 1;
  tcph->rst     = 0;
  tcph->psh     = 0;
  tcph->ack     = 0;
  tcph->urg     = 0;
  tcph->res2    = 0;
  tcph->window  = htons(512);
  tcph->check   = 0;
  tcph->urg_ptr = htons(0);

  // now we compute the TCP header checksum, across a pseudo message buffer, not the actual TCP header
  unsigned short* buffer = 0;
  unsigned int    bufferSize = buildPseudoHdrBuffer(src_sin->sin_addr.s_addr, dst_sin->sin_addr.s_addr, IPPROTO_TCP,
                                                    (const unsigned char*) tcph, sizeof(struct tcphdr),
                                                    msg, msgSize, &buffer);

  tcph->check = c_sum(buffer, bufferSize);
  free(buffer);

  // add message data (if any)
  if (msgSize > 0)
  {
    memcpy(data, msg, msgSize);
  }

  return datagram;
}


unsigned int buildPseudoHdrBuffer(unsigned int src_addr, unsigned int dst_addr, unsigned int protocol,
                                  const unsigned char* hdrData, unsigned int hdrBytes,
                                  const unsigned char* msgData, unsigned int msgBytes,
                                  unsigned short** buffer)
{
  struct PseudoHdr pseudoHdr;

  pseudoHdr.saddr    = src_addr;
  pseudoHdr.daddr    = dst_addr;
  pseudoHdr.reserved = 0;
  pseudoHdr.protocol = protocol;
  pseudoHdr.length   = htons(hdrBytes + msgBytes);

  unsigned int   bufSize = sizeof(struct PseudoHdr) + hdrBytes + msgBytes;
  unsigned char* buf     = calloc(1, bufSize);
  int            offset  = 0;

  memcpy(buf + offset, &pseudoHdr, sizeof(struct PseudoHdr)); offset += sizeof(struct PseudoHdr);
  memcpy(buf + offset, hdrData, hdrBytes); offset += hdrBytes;
  memcpy(buf + offset, msgData, msgBytes);

  *buffer = (uint16_t*) buf;

  return bufSize;
}
