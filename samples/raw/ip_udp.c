
#include <stdio.h>

#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>

#define NDEBUG
#define COUNTMAX 3000
#define MAX_FAKE 100
#define ERROR    -1
#define TYPE_A   1
#define TYPE_PTR 12
#define CLASS_INET 1
#define ERROR -1

#ifndef IPVERSION
	#define IPVERSION 4
#endif

#ifndef IP_MAXPACKET
	#define IP_MAXPACKET 65535
#endif

#define DNSHDRSIZE 12

#define IPHDRSIZE  sizeof(struct iphdr)
#define UDPHDRSIZE sizeof(struct udphdr)

unsigned short ip_check_sum (char *buf, int nwords)
{
	unsigned long sum;
	for (sum = 0; nwords > 0; nwords--) {
		sum += *buf++;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

uint16_t udp_check_sum(const void *buff, size_t len, unsigned long src_addr, unsigned long dest_addr)
{
	const uint16_t *buf = buff;
	uint16_t *ip_src = (void *) &src_addr, *ip_dst = (void *) &dest_addr;
	uint32_t sum;
	size_t length=len;
	
	/* Calculate the sum */
	sum = 0;
	while (len > 1) {
		sum += *buf++;
		if (sum & 0x80000000) {
			sum = (sum & 0xFFFF) + (sum >> 16);
		}
		len -= 2;
	}
	
	if (len & 1) {
		/* Add the padding if the packet lenght is odd */
		sum += *((uint8_t *)buf);
	}
	
	/* Add the pseudo-header */
	sum += *(ip_src++);
	sum += *ip_src;
	
	sum += *(ip_dst++);
	sum += *ip_dst;
	
	sum += htons(IPPROTO_UDP);
	sum += htons(length);
	
	/* Add the carries */
	while (sum >> 16) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}
	
	/* Return the one's complement of sum */
	return ( (uint16_t)(~sum)  );
}

int udp_send(int s, unsigned long saddr, unsigned long daddr, unsigned short sport, unsigned short dport, char *datagram, unsigned datasize)
{
	struct sockaddr_in sin;
	struct   iphdr  *ip;
	struct   udphdr *udp;
	unsigned char   *data;
	unsigned char   packet[4024];
	
	ip   = (struct iphdr  *)  packet;
	udp  = (struct udphdr *) (packet + IPHDRSIZE);
	data = (unsigned char *) (packet + IPHDRSIZE + UDPHDRSIZE);
	
	memset(packet, 0, sizeof(packet));
	
	udp->source = htons(sport);
	udp->dest   = htons(dport);
	udp->len    = htons(UDPHDRSIZE + datasize);
	
	memcpy(data, datagram, datasize);
	
//	ip->saddr  = inet_addr("192.168.128.8"); //saddr;
//	ip->daddr  = inet_addr("173.194.35.201"); //daddr;
	
	ip->saddr  = inet_addr("192.168.128.8"); //saddr;
	ip->daddr  = inet_addr("192.168.128.1"); //daddr;
	ip->version  = 4;             /*ip version*/
	ip->ihl      = 5;
	ip->ttl      = 245;
	ip->id       = random()%5985;
	ip->protocol = IPPROTO_UDP;   /*protocol type*/
	ip->tot_len  = htons((IPHDRSIZE + UDPHDRSIZE + datasize));
	ip->check    = 0;
	//ip->check    = ip_check_sum((char *) packet, IPHDRSIZE);
	
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = ip->daddr;
	sin.sin_port = udp->dest;
	
	printf ("socket: %d, packet: %s,size: %d, struct addr: %p, size: %i\n", s, packet, IPHDRSIZE + UDPHDRSIZE + datasize, (struct sockaddr *) &sin, sizeof(struct sockaddr));
	
	udp->check = udp_check_sum(udp, UDPHDRSIZE+datasize, ip->saddr, ip->daddr);
	
	return sendto(s, packet, IPHDRSIZE + UDPHDRSIZE + datasize, 0, (struct sockaddr *) &sin, sizeof(struct sockaddr));
}

int main(int argc, const char *argv[])
{
	int s = socket (AF_INET, SOCK_RAW, IPPROTO_UDP);
	{
		int on = 1;
		const int *val = &on;
		if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof(on)) < 0) {
			printf ("Warning: Cannot set HDRINCL!\n");
		}
	}
	
	if (udp_send(s, 0, 0, 1234, 4321, "hello\n\0", 7) < 0) {
		perror("sendto");
	}
	
	return 0;
}


