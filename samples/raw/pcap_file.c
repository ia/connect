
/*
 * spec sources:
 *  - http://wiki.wireshark.org/Development/LibpcapFileFormat/
 *  - http://www.tcpdump.org/linktypes.html
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <asm/types.h>
#include <stdlib.h>

typedef __u32  guint32;
typedef __u16  guint16;
typedef   int   gint32;

/* global header | [ packet header | packet data ] | [ packet header | packet data ] | ... */

typedef struct pcap_hdr_s {
	guint32 magic_number;   /* magic number */
	guint16 version_major;  /* major version number */
	guint16 version_minor;  /* minor version number */
	gint32  thiszone;       /* GMT to local correction */
	guint32 sigfigs;        /* accuracy of timestamps */
	guint32 snaplen;        /* max length of captured packets, in octets */
	guint32 network;        /* data link type */
} /*__attribute__((packed))*/ pcap_hdr_t;

typedef struct pcaprec_hdr_s {
	guint32 ts_sec;         /* timestamp seconds */
	guint32 ts_usec;        /* timestamp microseconds */
	guint32 incl_len;       /* number of octets of packet saved in file */
	guint32 orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

int main(int argc, char const* argv[])
{
	if (argc != 2) {
		printf("usage: %s pcap-file\n", argv[0]);
		return 1;
	}
	
	int fd = open(argv[1], O_RDONLY);
	if (fd == -1) {
		perror("open");
		return 1;
	}
	
	int pcap_hdr_l = sizeof(pcap_hdr_t);
	pcap_hdr_t *pcap_header = malloc(pcap_hdr_l);
	int hdr_l = read(fd, pcap_header, pcap_hdr_l);
	if (hdr_l != pcap_hdr_l) {
		perror("read");
	}
	
	printf("\n\tdump header pcap file\n");
	printf(" magic_number : 0x%X\n",      pcap_header->magic_number);
	printf(" version mj   : 0x%X\n",      pcap_header->version_major);
	printf(" version mn   : 0x%X\n",      pcap_header->version_minor);
	printf(" thiszone     : 0x%X\n",      pcap_header->thiszone);
	printf(" snaplen      : 0x%X ( %d )\n", pcap_header->snaplen, pcap_header->snaplen);
	printf(" network      : 0x%X\n",      pcap_header->network);
	
	int pcap_pkthdr_l = sizeof(pcaprec_hdr_t);
	pcaprec_hdr_t *pcap_pktheader = malloc(pcap_pkthdr_l);
	int pkthdr_l = read(fd, pcap_pktheader, pcap_pkthdr_l);
	if (hdr_l != pcap_pkthdr_l) {
		perror("  read");
		printf("   hdr_l         : %d\n", hdr_l);
		printf("   pcap_pkthdr_l : %d\n", pcap_pkthdr_l);
	}
	
	printf("\n\tdump header pcap packet\n");
	printf(" ts_sec       : %X\n", pcap_pktheader->ts_sec);
	printf(" ts_usec      : %X\n", pcap_pktheader->ts_usec);
	printf(" incl_len     : %X ( %d )\n", pcap_pktheader->incl_len, pcap_pktheader->incl_len);
	printf(" orig_len     : %X ( %d )\n", pcap_pktheader->orig_len, pcap_pktheader->orig_len);
	
	void *pkt = malloc(pcap_pktheader->incl_len);
	int pkt_l = read(fd, pkt, pcap_pktheader->incl_len);
	if (pkt_l != pcap_pktheader->incl_len) {
		perror("read");
	}
	
	printf("\n\tdump first pcap packet\n");
	int i;
	int h = 0;
	for (i = 0; i < pcap_pktheader->incl_len; i++) {
		if ((i % 16 == 0)) {
			printf("\n");
		}
		if ((i % 16 == 0)) {
			printf("\t0x%04x: ", h);
			h += 16;
		}
		if (i % 2 == 0) {
			printf(" ");
		}
		printf("%02x", *((unsigned char *) pkt + i));
	}
	
	printf("\n\n");
	
	close(fd);
	
	return 0;
}

