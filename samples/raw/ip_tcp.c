
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

#include <stdio.h>
#include <netinet/tcp.h> //Provides declarations for tcp header
#include <netinet/ip.h> //Provides declarations for ip header
 
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
 
int main (void)
{
 //Create a raw socket
 int s = socket (AF_INET, SOCK_RAW, IPPROTO_TCP);
 //Datagram to represent the packet
 char datagram[8192];
 //IP header
 struct iphdr *iph = (struct iphdr *) datagram;
 //TCP header
 struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
 struct sockaddr_in sin;
   
 sin.sin_family = AF_INET;
 sin.sin_port = htons(40);
 sin.sin_addr.s_addr = inet_addr ("127.0.0.1");
  
 memset (datagram, '1', 8192); /* zero out the buffer */
  
 //Fill in the IP Header
 iph->ihl = 5;
 iph->version = 4;
 iph->tos = 0;
 iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
printf("ip: %d\n", sizeof(struct ip));
printf("iphdr: %d\n", sizeof(struct iphdr));
printf("tcphdr: %d\n", sizeof(struct tcphdr));
 iph->id = htonl (54321); //Id of this packet
 iph->frag_off = 0;
 iph->ttl = 255;
 iph->protocol = 6;
 iph->check = 0;  //Set to 0 before calculating checksum
 iph->saddr = inet_addr ("1.2.3.4"); //Spoof the source ip address
 iph->daddr = sin.sin_addr.s_addr;
  
 //TCP Header
 tcph->source = htons (1234);
 tcph->dest = htons (85);
 tcph->seq = random ();
 tcph->ack_seq = 0;
 tcph->doff = 0;  /* first and only tcp segment */
 tcph->syn = 1;
 tcph->window = htonl (65535); /* maximum allowed window size */
 tcph->check = 0;/* if you set a checksum to zero, your kernel's IP stack
    should fill in the correct checksum during transmission */
 tcph->urg_ptr = 0;
 //Now the IP checksum
 iph->check = csum ((unsigned short *) datagram, iph->tot_len >> 1);
  
 //IP_HDRINCL to tell the kernel that headers are included in the packet
 {
  int one = 1;
  const int *val = &one;
  if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
   printf ("Warning: Cannot set HDRINCL!\n");
 }
  
// while (1)
// {
  //Send the packet
//  if (sendto (s,  /* our socket */
//     datagram, /* the buffer containing headers and data */
//     20, //iph->tot_len, /* total length of our datagram */
//     0,  /* routing flags, normally always 0 */
//     (struct sockaddr *) &sin, /* socket addr, just like in */
//     sizeof (sin)) < 0)  /* a normal send() */
//   printf ("error\n");
//  else
//   printf (".\n");
// }

  if ((sendto (s, datagram, 40, 0, (struct sockaddr *) &sin, sizeof (sin))) < 0) {
   printf ("error\n");
  } else {
   printf (".\n");
  }

 return 0;
}
