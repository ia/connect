
/*
 * spec sources:
 *  - http://wiki.wireshark.org/Development/LibpcapFileFormat/
 *  - http://www.tcpdump.org/linktypes.html
 *  - http://v2.nat32.com/pcap.htm
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <asm/types.h>

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

/*
magic_number:   used to detect the file format itself and the byte ordering. The writing application writes
                0xa1b2c3d4 with it's native byte ordering format into this field. The reading application will
                read either 0xa1b2c3d4 (identical) or 0xd4c3b2a1 (swapped). If the reading application reads
                the swapped 0xd4c3b2a1 value, it knows that all the following fields will have to be swapped too.
version_major,
version_minor:  the version number of this file format (current version is 2.4)
thiszone:       the correction time in seconds between GMT (UTC) and the local timezone of the following packet
                header timestamps. Examples: If the timestamps are in GMT (UTC), thiszone is simply 0.
                If the timestamps are in Central European time (Amsterdam, Berlin, ...) which is GMT + 1:00,
                thiszone must be -3600. In practice, time stamps are always in GMT, so thiszone is always 0.
sigfigs:        in theory, the accuracy of time stamps in the capture; in practice, all tools set it to 0
snaplen:        the "snapshot length" for the capture (typically 65535 or even more, but might be limited by
                the user), see: incl_len vs. orig_len below

network:        data link layer type (e.g. 1 for Ethernet, see wiretap/libpcap.c or libpcap's pcap-bpf.h for details),
                this can be various types like Token Ring, FDDI, etc.
*/

typedef struct pcaprec_hdr_s {
	guint32 ts_sec;         /* timestamp seconds */
	guint32 ts_usec;        /* timestamp microseconds */
	guint32 incl_len;       /* number of octets of packet saved in file */
	guint32 orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

/*
ts_sec:         the date and time when this packet was captured. This value is in seconds since January 1, 1970
                00:00:00 GMT; this is also known as a UN*X time_t. You can use the ANSI C time() function from
                time.h to get this value, but you might use a more optimized way to get this timestamp value.
                If this timestamp isn't based on GMT (UTC), use thiszone from the global header for adjustments.

ts_usec:        the microseconds when this packet was captured, as an offset to ts_sec.  Beware: this value
                shouldn't reach 1 second (1 000 000), in this case ts_sec must be increased instead!

incl_len:       the number of bytes of packet data actually captured and saved in the file. This value should
                never become larger than orig_len or the snaplen value of the global header.

orig_len:       the length of the packet as it appeared on the network when it was captured. If incl_len and
                orig_len differ, the actually saved packet size was limited by snaplen

*/

int file_write_header(const char *pcap_file)
{
	return 0;
}

int file_write(const char *pcap_file, int fd)
{
	return 0;
}

int file_read_header(const char *pcap_file)
{
	int fd = open(pcap_file, O_RDONLY);
	if (fd == -1) {
		perror("open");
		return errno;
	}
	
	int pcap_hdr_l = sizeof(pcap_hdr_t);
	pcap_hdr_t *pcap_hdr = malloc(pcap_hdr_l);
	if (!pcap_hdr) {
		perror("malloc");
		return ENOMEM;
	}
	
	int hdr_l = read(fd, pcap_hdr, pcap_hdr_l);
	if (hdr_l != pcap_hdr_l) {
		perror("read");
		return errno;
	}
	
	printf("\n\tdump header pcap file\n");
	printf(" magic_number : 0x%X\n",        pcap_hdr->magic_number);
	printf(" version mj   : 0x%X\n",        pcap_hdr->version_major);
	printf(" version mn   : 0x%X\n",        pcap_hdr->version_minor);
	printf(" thiszone     : 0x%X ( %d )\n", pcap_hdr->thiszone, pcap_hdr->thiszone);
	printf(" snaplen      : 0x%X ( %d )\n", pcap_hdr->snaplen, pcap_hdr->snaplen);
	printf(" network      : 0x%X\n",        pcap_hdr->network);
	
	return fd;
}

int file_read(const char *pcap_file, int fd)
{
	int pd = -1;
	
	if (pcap_file) {
		pd = file_read_header(pcap_file);
	} else {
		pd = fd;
	}
	
	int pcap_pkt_hdr_l = sizeof(pcaprec_hdr_t);
	pcaprec_hdr_t *pcap_pkt_hdr = malloc(pcap_pkt_hdr_l);
	
	int pkt_hdr_r = read(pd, pcap_pkt_hdr, pcap_pkt_hdr_l);
	if (pkt_hdr_r != pcap_pkt_hdr_l) {
		perror("read");
		printf(" pcap_pkt_hdr_l : %d\n", pcap_pkt_hdr_l);
		printf("      pkt_hdr_r : %d\n", pkt_hdr_r);
	}
	
	printf("\n\tdump header for first pcap packet\n");
	printf(" ts_sec       : %X\n",        pcap_pkt_hdr->ts_sec);
	printf(" ts_usec      : %X\n",        pcap_pkt_hdr->ts_usec);
	printf(" incl_len     : %X ( %d )\n", pcap_pkt_hdr->incl_len, pcap_pkt_hdr->incl_len);
	printf(" orig_len     : %X ( %d )\n", pcap_pkt_hdr->orig_len, pcap_pkt_hdr->orig_len);
	
	void *pkt = malloc(pcap_pkt_hdr->incl_len);
	int pkt_l = read(pd, pkt, pcap_pkt_hdr->incl_len);
	if (pkt_l != pcap_pkt_hdr->incl_len) {
		perror("read");
	}
	
	printf("\n\tdump first pcap packet\n");
	unsigned int i;
	unsigned int h = 0;
	for (i = 0; i < pcap_pkt_hdr->incl_len; i++) {
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
	
	close(pd);
	
	return 0;
}

int usage(const char *name)
{
	printf("usage: %s [r|w] pcap-file\n", name);
	return 0;
}

int main(int argc, const char* argv[])
{
	if (argc != 3) {
		usage(argv[0]);
		return 1;
	}
	
	int fd = -1;
	
	if (!strcmp(argv[1], "r")) {
		fd = file_read(argv[2], 0);
	} else if (!strcmp(argv[1], "w")) {
		fd = file_write(argv[2], 0);
	} else {
		printf("Error: unsupported operation: %s\n", argv[1]);
		usage(argv[0]);
		return 2;
	}
	
	if (fd) {
		close(fd);
	}
	
	return 0;
}

