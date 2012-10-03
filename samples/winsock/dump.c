
#include "stdio.h"
#include "winsock2.h"

#pragma comment(lib,"ws2_32.lib") //For winsock

#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1) //this removes the need of mstcpip.h

/* prototypes */

void packet_recv (SOCKET Sock); //This will sniff here and there
void ProcessPacket (char* , int); //This will decide how to digest
void PrintIpHeader (char*);
void PrintIcmpPacket (char* , int);
void PrintUdpPacket (char* , int);
void PrintTcpPacket (char* , int);
void ConvertToHex (char* , unsigned int);
void PrintData (char* , int);

/* datatypes */

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
} IPV4_HDR;

typedef struct udp_hdr
{
	unsigned short source_port; // Source port no.
	unsigned short dest_port; // Dest. port no.
	unsigned short udp_length; // Udp packet length
	unsigned short udp_checksum; // Udp checksum (optional)
} UDP_HDR;

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
} TCP_HDR;

typedef struct icmp_hdr
{
	BYTE type; // ICMP Error type
	BYTE code; // Type sub code
	USHORT checksum;
	USHORT id;
	USHORT seq;
} ICMP_HDR;

/* global vars */

FILE *logfile;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;
struct sockaddr_in source,dest;
char hex[2];

//Its free!
IPV4_HDR *iphdr;
TCP_HDR *tcpheader;
UDP_HDR *udpheader;
ICMP_HDR *icmpheader;

/* implementation */

void packet_callback(char *packet, int len)
{
	int i;
	for (i = 0; i < len; i++) {
		printf("%02X", *((unsigned char *) packet + i));
		if (i == 14) {
			printf("\n");
			break;
		} else {
			printf(" ");
		}
	}
	return 0;
}

void packet_recv(SOCKET sniffer)
{
	char *Buffer = (char *)malloc(65536); //Its Big!
	int mangobyte;
	
	if (Buffer == NULL) {
		printf("malloc() failed.\n");
		return;
	}
	
	do {
		mangobyte = recvfrom(sniffer , Buffer , 65536 , 0 , 0 , 0); //Eat as much as u can
		
		if (mangobyte > 0) {
			packet_callback(Buffer, mangobyte);
		} else {
			printf("recvfrom() failed.\n");
		}
	} while (mangobyte > 0);
	
	free(Buffer);
}

int main()
{
	SOCKET sniffer;
	struct in_addr addr;
	int in;
	
	char hostname[100];
	struct hostent *local;
	WSADATA wsa;
	
	// Init Winsock
	printf("\nInitialising Winsock... ");
	if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
		printf("WSAStartup() failed.\n");
		return 1;
	}
	printf("done\n");
	
	// Create a RAW Socket
	printf("Creating RAW Socket... ");
	//sniffer = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
	sniffer = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sniffer == INVALID_SOCKET) {
		printf("Failed to create raw socket.\n");
		return 1;
	}
	printf("Created.\n");
	
	// Retrive the local hostname
	if (gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR) {
		printf("Error : %d\n", WSAGetLastError());
		return 1;
	}
	printf("\nHost name : %s\n",hostname);
	
	// Retrive the available IPs of the local host
	local = gethostbyname(hostname);
	printf("\nAvailable Network Interfaces : \n");
	if (local == NULL) {
		printf("Error : %d\n", WSAGetLastError());
		return 1;
	}
	
	for (i = 0; local->h_addr_list[i] != 0; ++i) {
		memcpy(&addr, local->h_addr_list[i], sizeof(struct in_addr));
		printf("Interface Number : %d Address : %s\n", i, inet_ntoa(addr));
	}
	
	printf("Enter the interface number you would like to sniff : ");
	scanf("%d",&in);
	
	memset(&dest, 0, sizeof(dest));
	memcpy(&dest.sin_addr.s_addr, local->h_addr_list[in], sizeof(dest.sin_addr.s_addr));
	dest.sin_family = AF_INET;
	dest.sin_port = 0;
	
	printf("\nBinding socket to local system and port 0... ");
	if (bind(sniffer,(struct sockaddr *)&dest,sizeof(dest)) == SOCKET_ERROR)
	{
		printf("bind(%s) failed.\n", inet_ntoa(addr));
		return 1;
	}
	printf("Binding successful\n");
	
	// Enable this socket with the power to sniff : SIO_RCVALL is the key Receive ALL ;)
	
	j=1;
	printf("Setting socket to sniff...");
	if (WSAIoctl(sniffer, SIO_RCVALL, &j, sizeof(j), 0, 0, (LPDWORD) &in , 0 , 0) == SOCKET_ERROR)
	{
		printf("WSAIoctl() failed.\n");
		return 1;
	}
	printf("Socket set.\n");
	
	// Begin
	printf("Started Sniffing\n");
	printf("Packet Capture Statistics...\n");
	packet_recv(sniffer); //Happy Sniffing
	
	// End
	closesocket(sniffer);
	WSACleanup();
	
	return 0;
}

