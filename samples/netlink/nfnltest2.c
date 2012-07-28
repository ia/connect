/* nfnetlink test code, 2nd revision
 *
 * (C) 2000 by Harald Welte <laforge@gnumonks.org>
 *
 * This program is distributed under the terms of GNU GPL 
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
//#include <linux/netfilter_ipv4/ip_conntrack_tuple.h>

//#include "/usr/src/linux/net/ipv4/netfilter/nfnetlink.h"

/* The protocol-specific manipulable parts of the tuple: always in
   network order! */
union ip_conntrack_manip_proto
{
        /* Add other protocols here. */
        u_int16_t all;

        struct {
                u_int16_t port;
        } tcp;
        struct {
                u_int16_t port;
        } udp;
        struct {
                u_int16_t id;
        } icmp;
        struct {
                u_int16_t port;
        } sctp;
};

/* The manipulable part of the tuple. */
struct ip_conntrack_manip
{
        u_int32_t ip;
        union ip_conntrack_manip_proto u;
};

/* This contains the information to distinguish a connection. */
struct ip_conntrack_tuple
{
        struct ip_conntrack_manip src;

        /* These are the parts of the tuple which are fixed. */
        struct {
                u_int32_t ip;
                union {
                        /* Add other protocols here. */
                        u_int16_t all;

                        struct {
                                u_int16_t port;
                        } tcp;
                        struct {
                                u_int16_t port;
                        } udp;
                        struct {
                                u_int8_t type, code;
                        } icmp;
                        struct {
                                u_int16_t port;
                        } sctp;
                } u;

                /* The protocol. */
                u_int8_t protonum;

                /* The direction (for tuplehash) */
                u_int8_t dir;
        } dst;
};

#define BUFSIZE	1024
#define NIPQUAD(addr) \
        ((unsigned char *)&addr)[0], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[3]

void print_conntrack_tuple(struct ip_conntrack_tuple *t)
{
	FILE *f;

	f = stdout;

//	fprintf(f, "%u.%u.%u.%u -> %u.%u.%u.%u ",
//		NIPQUAD(t->src.ip), NIPQUAD(t->dst.ip));
//
//
//

	int temp = t->dst.protonum;


	switch (temp) {
		case IPPROTO_TCP:
			fprintf(f, "tcp %u:%u", ntohs(t->src.u.tcp.port), ntohs(t->dst.u.tcp.port));
			break;
		case IPPROTO_UDP:
			fprintf(f, "udp %u:%u", ntohs(t->src.u.udp.port), ntohs(t->dst.u.udp.port));
			break;
		case IPPROTO_ICMP:
			fprintf(f, "icmp %u.%u", t->dst.u.icmp.type, t->dst.u.icmp.code);
		default:
			break;
	}
	fprintf(f, " ");
}
int handle_nfnl_event(unsigned char *buf, size_t count)
{
	struct nlmsghdr *nlmsg;
	struct nfnl_ctr *evt;

	nlmsg = (struct nlmsghdr *) buf;

	evt = (struct nfnl_ctr *) NLMSG_DATA(nlmsg);

	switch (nlmsg->nlmsg_type) {
		case NLMSG_DONE:
			printf("DONE:   ");
			print_conntrack_tuple(&(evt->tuple));
			break;
		case NLMSG_NOOP:
			printf("NOOP:  ");
//			print_conntrack_tuple(&(evt->tuple));
			break;
		case NLMSG_ERROR:
			printf("ERROR:  ");
//			print_conntrack_tuple(&(evt->tuple));
			break;
		default:
			printf("unknown message received");
			break;
	}

	printf("\n");
	return 0;
}
int main()
{
	int fd, ret;
	struct sockaddr_nl sa;
	unsigned char buf[BUFSIZE];

	fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
	if (fd == -1) {
		fprintf(stderr, "some error occurred during socket()\n");
		exit(1);
	}
	sa.nl_family = AF_NETLINK;
	sa.nl_pid = getpid();
	sa.nl_groups = 1;	
	ret = bind(fd, (struct sockaddr *)&sa, sizeof(sa));
	if (ret == -1) {
		fprintf(stderr, "error during bind()\n");
		exit(1);
	}
	while (1) {
		ret = recv(fd, &buf, BUFSIZE, 0);
		if (ret > 0) 
			handle_nfnl_event(buf, ret);
	}
		
}
