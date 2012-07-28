
#include <netinet/in.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define BUFSIZE 8192

char gateway[255];

struct route_info {
	struct in_addr dst_addr;
	struct in_addr src_addr;
	struct in_addr gateway;
	char if_name[IF_NAMESIZE];
};

void print_gateway()
{
	printf("\ngateway: %s\n", gateway);
}

/* For printing the routes. */
void route_print(struct route_info *rt_info)
{
	char msg[512];
	
	/* Print Destination address */
	if (rt_info->dst_addr.s_addr != 0) {
		strcpy(msg,  inet_ntoa(rt_info->dst_addr));
	} else {
		sprintf(msg, "*.*.*.*\t");
	}
	fprintf(stdout, "%s\t", msg);
	
	/* Print Gateway address */
	if (rt_info->gateway.s_addr != 0) {
		strcpy(msg, (char *) inet_ntoa(rt_info->gateway));
	} else {
		sprintf(msg, "*.*.*.*\t");
	}
	fprintf(stdout, "%s\t", msg);
	
	/* Print Interface Name */
	fprintf(stdout, "%s\t", rt_info->if_name);
	
	/* Print Source address */
	if (rt_info->src_addr.s_addr != 0) {
		strcpy(msg, inet_ntoa(rt_info->src_addr));
	} else {
		sprintf(msg, "*.*.*.*\t");
	}
	fprintf(stdout, "%s\n", msg);
}

/* For parsing the route info returned */
void route_parse(struct nlmsghdr *nl_msg, struct route_info *rt_info)
{
	struct rtmsg *rt_msg;
	struct rtattr *rt_attr;
	int rt_len = 0;
	
	rt_msg = (struct rtmsg *) NLMSG_DATA(nl_msg);
	
	/* If the route is not for AF_INET or does not belong to main routing table then return. */
	if ((rt_msg->rtm_family != AF_INET) || (rt_msg->rtm_table != RT_TABLE_MAIN)) {
		return;
	}
	
	/* get the rtattr field */
	rt_attr = (struct rtattr *) RTM_RTA(rt_msg);
	rt_len = RTM_PAYLOAD(nl_msg);
	for (  ; RTA_OK(rt_attr, rt_len); rt_attr = RTA_NEXT(rt_attr, rt_len)) {
		switch (rt_attr->rta_type) {
			case RTA_OIF:
				if_indextoname(*(int *) RTA_DATA(rt_attr), rt_info->if_name);
				break;
			case RTA_GATEWAY:
				rt_info->gateway.s_addr= *(u_int *) RTA_DATA(rt_attr);
				break;
			case RTA_PREFSRC:
				rt_info->src_addr.s_addr= *(u_int *) RTA_DATA(rt_attr);
				break;
			case RTA_DST:
				rt_info->dst_addr .s_addr= *(u_int *) RTA_DATA(rt_attr);
				break;
		}
	}
	
	printf("==== %s ", rt_info->if_name);
	if (rt_info->gateway.s_addr != 0) {
		printf("%s", (char *) inet_ntoa(rt_info->gateway));
	} else {
		printf("%s", "*");
	}
	printf("\n");
	
	//printf("%s\n", inet_ntoa(rt_info->dst_addr));
	
	if (rt_info->dst_addr.s_addr == 0) {
		sprintf(gateway, "%s", (char *) inet_ntoa(rt_info->gateway));
	}
	
	//route_print(rt_info);
	
	return;
}

int socket_netlink_read(int sd, char *msg, int seq, int pid)
{
	struct nlmsghdr *nl_msg;
	int len_read = 0, len_msg = 0;
	
	do {
		/* Recieve response from the kernel */
		if ((len_read = recv(sd, msg, BUFSIZE - len_msg, 0)) < 0) {
			perror("SOCK READ: ");
			return -1;
		}
		
		nl_msg = (struct nlmsghdr *) msg;
		
		/* Check if the header is valid */
		if ((NLMSG_OK(nl_msg, len_read) == 0) || (nl_msg->nlmsg_type == NLMSG_ERROR)) {
			perror("Error in recieved packet");
			return -1;
		}
		
		/* Check if the its the last message */
		if (nl_msg->nlmsg_type == NLMSG_DONE) {
			break;
		} else {
			/* Else move the pointer to buffer appropriately */
			msg += len_read;
			len_msg += len_read;
		}
		
		/* Check if its a multi part message */
		if ((nl_msg->nlmsg_flags & NLM_F_MULTI) == 0) {
			/* return if its not */
			break;
		}
		
	} while ((nl_msg->nlmsg_seq != seq) || (nl_msg->nlmsg_pid != pid));
	
	return len_msg;
}

int main(int argc, const char *argv[])
{
	struct nlmsghdr *nl_msg;
	struct route_info *rt_info;
	char msg[BUFSIZE];
	
	int sd, len, msg_seq = 0;
	
	/* Create Socket */
	if ((sd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) < 0) {
		perror("Socket Creation: ");
	}
	
	memset(msg, 0, BUFSIZE);
	
	/* point the header and the msg structure pointers into the buffer */
	nl_msg = (struct nlmsghdr *) msg;
	
	/* Fill in the nlmsg header*/
	nl_msg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));  // Length of message
	nl_msg->nlmsg_type = RTM_GETROUTE; // Get the routes from kernel routing table
	
	nl_msg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST; // The message is a request for dump
	nl_msg->nlmsg_seq = msg_seq++; // Sequence of the message packet.
	nl_msg->nlmsg_pid = getpid(); // PID of process sending the request.
	
	/* Send the request */
	if (send(sd, nl_msg, nl_msg->nlmsg_len, 0) < 0) {
		printf("Write To Socket Failed...\n");
		return -1;
	}
	
	/* Read the response */
	if ((len = socket_netlink_read(sd, msg, msg_seq, getpid())) < 0) {
		printf("Read From Socket Failed...\n");
		return -1;
	}
	
	/* Parse and print the response */
	rt_info = (struct route_info *) malloc(sizeof(struct route_info));
	
	fprintf(stdout, "Destination\tGateway\tInterface\tSource\n");
	
	for ( ; NLMSG_OK(nl_msg, len); nl_msg = NLMSG_NEXT(nl_msg, len)) {
		memset(rt_info, 0, sizeof(struct route_info));
		route_parse(nl_msg, rt_info);
	}
	
	free(rt_info);
	close(sd);
	
	print_gateway();
	
	return 0;
}

