

/*
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 */


#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
/*
#define MY_DEST_MAC0	0x00
#define MY_DEST_MAC1	0x00
#define MY_DEST_MAC2	0x00
#define MY_DEST_MAC3	0x00
#define MY_DEST_MAC4	0x00
#define MY_DEST_MAC5	0x00
*/
#define DEFAULT_IF    "lo"
#define BUF_SIZ       1514


int main(int argc, char *argv[])
{
	int sockfd;
	struct ifreq if_idx;
	char sendbuf[BUF_SIZ];
	struct sockaddr_ll socket_address;
	char ifName[IFNAMSIZ];
	struct ether_header *eh = (struct ether_header *) sendbuf;
	
	/* Get interface name */
	if (argc > 1) {
		strcpy(ifName, argv[1]);
	} else {
		strcpy(ifName, DEFAULT_IF);
	}
	
	/* Open RAW socket to send on */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
	    perror("socket");
	}
	
	/* Get the index of the interface to send on */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0) {
	    perror("SIOCGIFINDEX");
	}
	
	memset(sendbuf, 0xFF, BUF_SIZ);
	
	/* Index of the network device */
	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	/* Address length*/
	socket_address.sll_halen = ETH_ALEN;
	/* Destination MAC */
	/*
	socket_address.sll_addr[0] = MY_DEST_MAC0;
	socket_address.sll_addr[1] = MY_DEST_MAC1;
	socket_address.sll_addr[2] = MY_DEST_MAC2;
	socket_address.sll_addr[3] = MY_DEST_MAC3;
	socket_address.sll_addr[4] = MY_DEST_MAC4;
	socket_address.sll_addr[5] = MY_DEST_MAC5;
	*/
	/* Send packet */
	if (sendto(sockfd, sendbuf, BUF_SIZ, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0) {
	    perror("send");
	}
	
	return 0;
}


