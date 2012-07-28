
/* IP header (RFC 791)

0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |         Header Checksum       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

/* TCP header (RFC 793)

0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |           |U|A|P|R|S|F|                               |
| Offset| Reserved  |R|C|S|S|Y|I|            Window             |
|       |           |G|K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             data                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

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
#define TCPHDRSIZE sizeof(struct tcphdr)
#define UDPHDRSIZE sizeof(struct udphdr)

#include <stdio.h>
#include <netinet/tcp.h> //Provides declarations for tcp header
#include <netinet/ip.h> //Provides declarations for ip header

#include <stdlib.h>

//Checksum calculation function
unsigned short csum (unsigned short *buf, int nwords)
{
 unsigned long sum;
  
 for (sum = 0; nwords > 0; nwords--)
  sum += *buf++;
  
 sum = (sum >> 16) + (sum & 0xffff);
 sum += (sum >> 16);
  
 return ~sum;
}

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

uint16_t tcp_check_sum(const void *buff, size_t len, unsigned long src_addr, unsigned long dest_addr)
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
	
	sum += htons(IPPROTO_TCP);
	sum += htons(length);
	
	/* Add the carries */
	while (sum >> 16) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}
	
	/* Return the one's complement of sum */
	return ( (uint16_t)(~sum)  );
}

int main (void)
{
	//Create a raw socket
	int s = socket (PF_INET, SOCK_RAW, IPPROTO_RAW);
	//Datagram to represent the packet
	//char datagram[8192];
	char datagram[] = "hello\n\0";
	int datasize = strlen(datagram);
	
	//IP_HDRINCL to tell the kernel that headers are included in the packet
	{
		int on = 1;
		const int *val = &on;
		if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (on)) < 0) {
			printf ("Warning: Cannot set HDRINCL!\n");
		}
	}
	
	struct sockaddr_in sin;
	struct   iphdr  *ip;
	struct   tcphdr *tcp;
	unsigned char   *data;
	unsigned char   packet[4024];
	
	ip   = (struct iphdr  *)  packet;
	tcp  = (struct tcphdr *) (packet + IPHDRSIZE);
	data = (unsigned char *) (packet + IPHDRSIZE + TCPHDRSIZE);
	
//	memset(packet, 0, sizeof(packet));
//	memset(packet, 0xA, 4);
	
	//TCP Header
//	tcp->source = htons (1234);
//	tcp->dest = htons (85);
//	tcp->seq = random ();
//	tcp->ack_seq = 0;
//	tcp->doff = 0;  /* first and only tcp segment */
//	tcp->syn = 1;
//	tcp->window = htonl (65535); /* maximum allowed window size */
//	tcp->check = 0; /* if you set a checksum to zero, your kernel's IP stack should fill in the correct checksum during transmission */
//	tcp->urg_ptr = 0;
#define Z_NL   4294967295
  tcp->source  = htons(1234);
  tcp->dest    = htons(4321);
  tcp->seq     = random(); //htonl((int)(rand()/(((double)RAND_MAX + 1)/Z_NL)));
  tcp->ack_seq = 0; //htonl(0);
//  tcp->res1    = 0;
  tcp->doff    = sizeof(struct tcphdr) >> 2;
//  tcp->fin     = 1;
  tcp->syn     = 1;
//  tcp->rst     = 0;
//  tcp->psh     = 0;
//  tcp->ack     = 0;
//  tcp->urg     = 0;
//  tcp->res2    = 0;
  tcp->window  = htons(512);
  tcp->check   = 0;
  tcp->urg_ptr = htons(0);


	memcpy(data, datagram, datasize);
	
	ip->saddr  = inet_addr("192.168.128.8"); //saddr;
	ip->daddr  = inet_addr("127.0.0.1"); //daddr;
	ip->version  = 4;             /*ip version*/
	ip->ihl      = 5;
	ip->ttl      = 255;
	ip->id       = random();
	ip->protocol = IPPROTO_TCP;   /*protocol type*/
	ip->tot_len  = htons((IPHDRSIZE + TCPHDRSIZE + datasize));
	ip->check    = 0;
	ip->check    = ip_check_sum((char *) packet, IPHDRSIZE);
	
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = ip->daddr;
	sin.sin_port = tcp->dest;
	
	tcp->check = tcp_check_sum(tcp, TCPHDRSIZE+datasize, ip->saddr, ip->daddr);
//	memset(packet, 0xA, 4);
	if ((sendto (s, packet, IPHDRSIZE + TCPHDRSIZE + datasize, 0, (struct sockaddr *) &sin, sizeof (struct sockaddr))) < 0) {
		printf ("error\n");
	} else {
		printf (".\n");
	}
	
	return 0;
}

