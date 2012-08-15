//raw tcp packet crafter

#include "stdio.h"
#include "winsock2.h"
#include "ws2tcpip.h" //IP_HDRINCL is here
#include "conio.h"

#pragma comment(lib,"ws2_32.lib") //winsock 2.2 library

typedef struct ip_hdr
{
unsigned char ip_header_len:4; // 4-bit header length (in 32-bit words) normally=5 (Means 20 Bytes may be 24 also)
unsigned char ip_version :4; // 4-bit IPv4 version
unsigned char ip_tos; // IP type of service
unsigned short ip_total_length; // Total length
unsigned short ip_id; // Unique identifier

unsigned char ip_frag_offset :5; // Fragment offset field

unsigned char ip_more_fragment :1;
unsigned char ip_dont_fragment :1;
unsigned char ip_reserved_zero :1;

unsigned char ip_frag_offset1; //fragment offset

unsigned char ip_ttl; // Time to live
unsigned char ip_protocol; // Protocol(TCP,UDP etc)
unsigned short ip_checksum; // IP checksum
unsigned int ip_srcaddr; // Source address
unsigned int ip_destaddr; // Source address
} IPV4_HDR, *PIPV4_HDR, FAR * LPIPV4_HDR;

// TCP header
typedef struct tcp_header
{
unsigned short source_port; // source port
unsigned short dest_port; // destination port
unsigned int sequence; // sequence number - 32 bits
unsigned int acknowledge; // acknowledgement number - 32 bits

unsigned char ns :1; //Nonce Sum Flag Added in RFC 3540.
unsigned char reserved_part1:3; //according to rfc
unsigned char data_offset:4; /*The number of 32-bit words in the TCP header.
This indicates where the data begins.
The length of the TCP header is always a multiple
of 32 bits.*/

unsigned char fin :1; //Finish Flag
unsigned char syn :1; //Synchronise Flag
unsigned char rst :1; //Reset Flag
unsigned char psh :1; //Push Flag
unsigned char ack :1; //Acknowledgement Flag
unsigned char urg :1; //Urgent Flag

unsigned char ecn :1; //ECN-Echo Flag
unsigned char cwr :1; //Congestion Window Reduced Flag

////////////////////////////////

unsigned short window; // window
unsigned short checksum; // checksum
unsigned short urgent_pointer; // urgent pointer
} TCP_HDR , *PTCP_HDR , FAR * LPTCP_HDR , TCPHeader , TCP_HEADER;

int main()
{
char host[100],buf[1000],*data=NULL,source_ip[20]; //buf is the complete packet
SOCKET s;
int k=1;

IPV4_HDR *v4hdr=NULL;
TCP_HDR *tcphdr=NULL;

int payload=512 , optval;
SOCKADDR_IN dest;
hostent *server;

//Initialise Winsock
WSADATA wsock;
printf("\nInitialising Winsock...");
if (WSAStartup(MAKEWORD(2,2),&wsock) != 0)
{
fprintf(stderr,"WSAStartup() failed");
exit(EXIT_FAILURE);
}
printf("Initialised successfully.");
////////////////////////////////////////////////

//Create Raw TCP Packet
printf("\nCreating Raw TCP Socket...");
if((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW))==SOCKET_ERROR)
{
printf("Creation of raw socket failed.");
return 0;
}
printf("Raw TCP Socket Created successfully.");
////////////////////////////////////////////////

//Put Socket in RAW Mode.
printf("\nSetting the socket in RAW mode...");
if(setsockopt(s, IPPROTO_IP, IP_HDRINCL, (char *)&optval, sizeof(optval))==SOCKET_ERROR)
{
printf("failed to set socket in raw mode.");
return 0;
}
printf("Successful.");
////////////////////////////////////////////////

//Target Hostname
printf("\nEnter hostname : ");
gets(host);
printf("\nResolving Hostname...");
if((server=gethostbyname(host))==0)
{
printf("Unable to resolve.");
return 0;
}
dest.sin_family = AF_INET;
dest.sin_port = htons(50000); //your destination port
memcpy(&dest.sin_addr.s_addr,server->h_addr,server->h_length);
printf("Resolved.");
/////////////////////////////////////////////////

printf("\nEnter Source IP : ");
gets(source_ip);

v4hdr = (IPV4_HDR *)buf; //lets point to the ip header portion
v4hdr->ip_version=4;
v4hdr->ip_header_len=5;
v4hdr->ip_tos = 0;
v4hdr->ip_total_length = htons ( sizeof(IPV4_HDR) + sizeof(TCP_HDR) + payload );
v4hdr->ip_id = htons(2);
v4hdr->ip_frag_offset = 0;
v4hdr->ip_frag_offset1 = 0;
v4hdr->ip_reserved_zero = 0;
v4hdr->ip_dont_fragment = 1;
v4hdr->ip_more_fragment = 0;
v4hdr->ip_ttl = 8;
v4hdr->ip_protocol = IPPROTO_TCP;
v4hdr->ip_srcaddr = inet_addr(source_ip);
v4hdr->ip_destaddr = inet_addr(inet_ntoa(dest.sin_addr));
v4hdr->ip_checksum = 0;

tcphdr = (TCP_HDR *)&buf[sizeof(IPV4_HDR)]; //get the pointer to the tcp header in the packet

tcphdr->source_port = htons(1234);
tcphdr->dest_port = htons(50000);

tcphdr->cwr=0;
tcphdr->ecn=1;
tcphdr->urg=0;
tcphdr->ack=0;
tcphdr->psh=0;
tcphdr->rst=1;
tcphdr->syn=0;
tcphdr->fin=0;
tcphdr->ns=1;

tcphdr->checksum = 0;

// Initialize the TCP payload to some rubbish
data = &buf[sizeof(IPV4_HDR) + sizeof(TCP_HDR)];
memset(data, '^', payload);

printf("\nSending packet...\n");

while(!_kbhit())
{
printf(" %d packets send\r",k++);
if((sendto(s , buf , sizeof(IPV4_HDR)+sizeof(TCP_HDR) + payload, 0,
(SOCKADDR *)&dest, sizeof(dest)))==SOCKET_ERROR)
{

printf("Error sending Packet : %d",WSAGetLastError());
break;
}
}

return 0;
}


