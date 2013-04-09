

/*
 *  Linux Packet Memory Mapping sample - receiving
 * http://wiki.ipxwarzone.com/index.php5?title=Linux_packet_mmap
 * https://git.kernel.org/cgit/linux/kernel/git/stable/linux-stable.git/tree/Documentation/networking/packet_mmap.txt
 */


/* Copyright (c) 2002 Gianni Tedesco
 * Released under the terms of the GNU GPL version 2
 * mmap() packet socket based packet sniffer
*/

#ifndef __linux__
#error "Are you loco? This is Linux only!"
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#define __USE_XOPEN
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <features.h>    /* for the glibc version number */
#if __GLIBC__ >= 2 && __GLIBC_MINOR >= 1
#include <netpacket/packet.h>
#include <net/ethernet.h>     /* the L2 protocols */
#else
#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>   /* The L2 protocols */
#endif
#include <string.h>
#include <netinet/in.h>
// #include <asm/system.h> for mb() - not available
#include <signal.h>

char *names[]={
	"<", /* incoming */
	"B", /* broadcast */
	"M", /* multicast */
	"P", /* promisc */
	">", /* outgoing */
};

int fd=-1;
char *map;
struct tpacket_req req;
struct iovec *ring;

void sigproc(int sig)
{
	struct tpacket_stats st;
	int len=sizeof(st);

	if (!getsockopt(fd,SOL_PACKET,PACKET_STATISTICS,(char *)&st,&len)) {
		fprintf(stderr, "recieved %u packets, dropped %u\n",
			st.tp_packets, st.tp_drops);
	}
	
	if ( map ) munmap(map, req.tp_block_size * req.tp_block_nr);
	if ( fd>=0 ) close(fd);
	if ( ring ) free(ring);

	exit(0);
}

int main ( int argc, char **argv ) 
{
	struct pollfd pfd;
	struct sockaddr_ll addr;
	int i;
	
	signal(SIGINT, sigproc);

	/* Open the packet socket */
	if ( (fd=socket(PF_PACKET, SOCK_DGRAM, 0))<0 ) {
		perror("socket()");
		return 1;
	}

	/* Setup the fd for mmap() ring buffer */
	req.tp_block_size=4096;
	req.tp_frame_size=1024;
	req.tp_block_nr=64;
	req.tp_frame_nr=4*64;
	if ( (setsockopt(fd,
		SOL_PACKET,
		PACKET_RX_RING,
		(char *)&req,
		sizeof(req))) != 0 ) {
		perror("setsockopt()");
		close(fd);
		return 1;
	};

	/* mmap() the sucker */
	map=mmap(NULL,
		req.tp_block_size * req.tp_block_nr,
		PROT_READ|PROT_WRITE|PROT_EXEC, MAP_SHARED, fd, 0);
	if ( map==MAP_FAILED ) {
		perror("mmap()");
		close(fd);
		return 1;
	}

	/* Setup our ringbuffer */
	ring=malloc(req.tp_frame_nr * sizeof(struct iovec));
	for(i=0; i<req.tp_frame_nr; i++) {
		ring[i].iov_base=(void *)((long)map)+(i*req.tp_frame_size);
		ring[i].iov_len=req.tp_frame_size;
	}
	
	/* bind the packet socket */
	memset(&addr, 0, sizeof(addr));
	addr.sll_family=AF_PACKET;
	addr.sll_protocol=htons(0x03);
	addr.sll_ifindex=0;
	addr.sll_hatype=0;
	addr.sll_pkttype=0;
	addr.sll_halen=0;
	if ( bind(fd, (struct sockaddr *)&addr, sizeof(addr)) ) {
		munmap(map, req.tp_block_size * req.tp_block_nr);
		perror("bind()");
		close(fd);
		return 1;
	}
	
	for(i=0;;) {
		while(*(unsigned long*)ring[i].iov_base) {
			struct tpacket_hdr *h=ring[i].iov_base;
			struct sockaddr_ll *sll=(void *)h + TPACKET_ALIGN(sizeof(*h));
			unsigned char *bp=(unsigned char *)h + h->tp_mac;

			printf("%u.%.6u: if%u %s %u bytes\n",
				h->tp_sec, h->tp_usec,
				sll->sll_ifindex,
				names[sll->sll_pkttype],
				h->tp_len);

			/* tell the kernel this packet is done with */
			h->tp_status=0;
			__sync_synchronize(); // in GCC 4.4+ //mb(); /* memory barrier */
			
			i=(i==req.tp_frame_nr-1) ? 0 : i+1;
		}

		/* Sleep when nothings happening */
		pfd.fd=fd;
		pfd.events=POLLIN|POLLERR;
		pfd.revents=0;
		poll(&pfd, 1, -1);
	}
	
	return 0;
}


