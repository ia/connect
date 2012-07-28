
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#include <linux/ip.h>
#include <linux/if_ether.h>

#include "nlnf.h"

#define NETLINK_NETFILTER_NG NETLINK_USERSOCK

/* maximum payload size */
#define MAX_PAYLOAD  4096

#define MAC_HTOP(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3], \
    ((unsigned char *)&addr)[4], \
    ((unsigned char *)&addr)[5]

int sd;

struct sockaddr_nl src_addr, dest_addr;
struct nlmsghdr *nlh = NULL;
struct iovec iov;
struct msghdr msg;

int main(int argc, const char *argv[])
{
	sd = socket(PF_NETLINK, SOCK_RAW, NETLINK_NETFILTER_NG);
	if (sd == -1) {
		perror("socket");
		return -1;
	}
	
	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid();
	
	/* interested in group 1<<0 */
	if (bind(sd, (struct sockaddr*) &src_addr, sizeof(src_addr)) != 0) {
		perror("bind");
		return -1;
	}
	
	memset(&dest_addr, 0, sizeof(dest_addr));
	memset(&dest_addr, 0, sizeof(dest_addr));
	
	dest_addr.nl_family = AF_NETLINK;
	/* kernel */
	dest_addr.nl_pid = 0;
	/* unicast */
	dest_addr.nl_groups = 0;
	
	nlh = (struct nlmsghdr *) malloc(NLMSG_SPACE(MAX_PAYLOAD));
	memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
	nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_flags = 0;
	
	struct nlnf_pf *pf;
	pf = malloc(sizeof (struct nlnf_pf));
	pf->filter = 257;
	
	pf->hw_addr_dest[0] = 0xFF;
	pf->hw_addr_dest[1] = 0xFF;
	pf->hw_addr_dest[2] = 0xFF;
	pf->hw_addr_dest[3] = 0xFF;
	pf->hw_addr_dest[4] = 0xFF;
	pf->hw_addr_dest[5] = 0xFF;

	pf->hw_addr_src[0] = 0x68;
	pf->hw_addr_src[1] = 0xB5;
	pf->hw_addr_src[2] = 0x99;
	pf->hw_addr_src[3] = 0xF7;
	pf->hw_addr_src[4] = 0x0E;
	pf->hw_addr_src[5] = 0x88;
	
	//memset(pf->hw_addr_dest, 0xFF, 6); // = 0xFFFFFFFFFF;
	
	printf("(%02X:%02X:%02X:%02X:%02X:%02X)\n", MAC_HTOP(pf->hw_addr_dest));
	printf("(%02X)\n", pf->hw_addr_dest[0]);
	
	//strcpy(NLMSG_DATA(nlh), "Hello");
	strcpy(NLMSG_DATA(nlh), (void *) pf);
	
	iov.iov_base = (void *) nlh;
	iov.iov_len = nlh->nlmsg_len;
	
	msg.msg_name = (void *) &dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	
	printf("Sending message to kernel\n");
	
	sendmsg(sd, &msg, 0);
	
	printf("Waiting for message from kernel\n");
	
	/* Read message from kernel */
	recvmsg(sd, &msg, 0);
	
	printf(" Received message payload: %s\n", (char *) NLMSG_DATA(nlh));
//	struct nlnf_pkt *pkt;
	while (1) {
		recvmsg(sd, &msg, 0);
		
		/*
		unsigned char *b = malloc(6);
		memcpy(b, NLMSG_DATA(nlh), 6);
		printf("src: (%02X:%02X:%02X:%02X:%02X:%02X)\n", MAC_HTOP(*b));
		*/
		//pf_in = (NLMSG_DATA(nlh));
		//printf("src: (%02X:%02X:%02X:%02X:%02X:%02X)\n", MAC_HTOP(*(pf_in->eth_hdr->h_source)));

//		printf("src0: (%02X:%02X:%02X:%02X:%02X:%02X)\n", MAC_HTOP(*(NLMSG_DATA(nlh))));
//		printf("src1: (%02X:%02X:%02X:%02X:%02X:%02X)\n", MAC_HTOP(((struct nlnf *)(NLMSG_DATA(nlh)))->eth_hdr->h_source));
		
		//printf(" Received message payload: %s\n", (char *) NLMSG_DATA(nlh));
		
		//printf("src: (%02X:%02X:%02X:%02X:%02X:%02X)\n", MAC_HTOP(*(pf_in->eth_hdr->h_source)));
		//
		//printf("src0: (%02X)\n", ((struct nlnf *)(NLMSG_DATA(nlh)))->eth_hdr->h_source[0]);
		/*
		printf("filter: (%d)\n", ((struct nlnf *)(NLMSG_DATA(nlh)))->filter); //->eth_hdr->h_source[0]);
		printf("src0: (0x%x)\n", ((struct nlnf *)(NLMSG_DATA(nlh)))->eth_hdr); //->eth_hdr->h_source[0]);
		printf("src1: (0x%02X)\n", ((struct nlnf *)(NLMSG_DATA(nlh)))->hw_addr_src[0]); //->eth_hdr->h_source[0]);
		*/

		/*
		unsigned char *data = (unsigned char *) NLMSG_DATA(nlh);
		unsigned int l = strlen((const char *) data);
		printf("len: %d", l);
		int i;
		for (i = 0; i < l; i++) {
			printf(" %02X", data[i]);
		}
		printf("\nend\n");
		*/

		//struct nlnf_pkt *pkt = (void *) NLMSG_DATA(nlh);
		void *pkt = (void *) NLMSG_DATA(nlh);
		//unsigned int l = strlen((const char *) data);
	//	printf("mac_len: %02X : %d\n", pkt->mac_len, pkt->mac_len);
		
		int i;
		printf("mac_hdr:");
		for (i = 0; i < ((struct nlnf_pkt *) pkt)->mac_len; i++) {
		/*
			printf(" %02X", pkt);
			printf(" %02X", &pkt[0]);
			printf(" %02X", &pkt[1]);
		*/
			/* good one */
			printf(" %02X", *((unsigned char *) pkt + sizeof(__u16) + i));

			//printf(" %02X",  (((struct nlnf_pkt *) pkt)->mac_hdr) ) ;

			/*
			printf(" %02X", *((unsigned char *) pkt+1));
			printf(" %02X", *((unsigned char *) pkt+2));
			*/
//			printf(" %02X", pkt++);
	//		printf(" %02X", pkt[3]);
//			printf(" %02X", pkt[2]);
		//	printf(" %02X", pkt->mac_hdr[1]);
		}
		


		printf("\n");


		
	}
	
	close(sd);
	
	return 0;
}

