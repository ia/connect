
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <netinet/in.h>
#include <net/if.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/types.h>

#include <netinet/if_ether.h>

#ifndef SIOCGIFCONF
	#include <sys/sockio.h>
#endif

#define BUFSIZE 8192

struct route_info {
	struct in_addr dst_addr;
	struct in_addr src_addr;
	struct in_addr gateway;
	char if_name[IF_NAMESIZE];
};

struct iface {
	char *if_name;
	struct sockaddr *if_saddr_ipv4;
	struct sockaddr *if_saddr_ipv6;
	struct sockaddr *if_saddr_mask4;
	struct sockaddr *if_saddr_mask6;
	char *if_addr_ipv4;
	char *if_addr_ipv6;
	char *if_addr_mask4;
	char *if_addr_mask6;
	char *if_addr_gateway;
};

struct iface_list {
	struct iface      *ifl_data;
	struct iface_list *ifl_next;
};

int ifl_enum(struct iface_list *ifl)
{
	printf("ifl_enum:\n");
	while (ifl) {
		if (ifl->ifl_data) {
			printf("iface->if_name: %s\n", ifl->ifl_data->if_name);
		}
		ifl = ifl->ifl_next;
	}
	
	return 0;
}

int ifl_add(struct iface_list *ifl, struct iface *ifl_data)
{
	printf("ifl_add: %d: %s\n", __LINE__, ifl_data->if_name);
	
	struct iface_list *i;
	i = malloc(sizeof(struct iface_list));
	
	memcpy(i->ifl_data, ifl_data, sizeof(struct iface));
	i->ifl_next = NULL;
	
	while (ifl) {
		if (!ifl->ifl_next) {
			ifl->ifl_next = i;
			break;
		} else {
			ifl = ifl->ifl_next;
		}
	}
	
	printf("ifl_add: %d: %s\n", __LINE__, ifl_data->if_name);
	
	return 0;
}

int ifl_add_once(struct iface_list *ifl, struct iface *ifl_data)
{
	struct iface_list *i;
	i = malloc(sizeof(struct iface_list));
	i->ifl_data = malloc(sizeof(struct iface));
	
	memcpy(i->ifl_data, ifl_data, sizeof(struct iface));
	i->ifl_next = NULL;
	
	while (ifl) {
		if (ifl->ifl_data && strcmp(ifl->ifl_data->if_name, ifl_data->if_name) == 0) {
			return;
		} else if (!ifl->ifl_next) {
			ifl->ifl_next = i;
		} else {
			ifl = ifl->ifl_next;
		}
	}
}

int ifl_add_once_ng(struct iface_list *ifl, struct iface *ifl_data)
{
	//printf("ifl_add: %d: %s\n", __LINE__, ifl_data->if_name);
	//printf("ifl_host: %d: %s\n", __LINE__, ifl_data->if_addr_ipv4);
	
	struct iface_list *i;
	i = malloc(sizeof(struct iface_list));
	i->ifl_data = malloc(sizeof(struct iface));
	
	memcpy(i->ifl_data, ifl_data, sizeof(struct iface));
	i->ifl_next = NULL;
	
	while (ifl) {
		if (ifl->ifl_data && strcmp(ifl->ifl_data->if_name, ifl_data->if_name) == 0) {
			
			if (ifl_data->if_addr_ipv4 && !ifl->ifl_data->if_addr_ipv4) {
				int s = strlen(ifl_data->if_addr_ipv4);
				ifl->ifl_data->if_addr_ipv4 = malloc(s);
				memcpy(ifl->ifl_data->if_addr_ipv4, ifl_data->if_addr_ipv4, s);
				ifl->ifl_data->if_addr_ipv4[s] = '\0';
			}
			
			if (ifl_data->if_addr_ipv6 && !ifl->ifl_data->if_addr_ipv6) {
				int s = strlen(ifl_data->if_addr_ipv6);
				ifl->ifl_data->if_addr_ipv6 = malloc(s+1);
				memset(ifl->ifl_data->if_addr_ipv6, '\0', s+1);
				strncpy(ifl->ifl_data->if_addr_ipv6, ifl_data->if_addr_ipv6, s);
				//memcpy(ifl->ifl_data->if_addr_ipv6, ifl_data->if_addr_ipv6, s);
				//ifl->ifl_data->if_addr_ipv6[s] = '\0';
			}
			
			if (ifl_data->if_addr_mask4 && !ifl->ifl_data->if_addr_mask4) {
				int s = strlen(ifl_data->if_addr_mask4);
				ifl->ifl_data->if_addr_mask4 = malloc(s);
				memcpy(ifl->ifl_data->if_addr_mask4, ifl_data->if_addr_mask4, s);
				ifl->ifl_data->if_addr_mask4[s] = '\0';
			}
			
			if (ifl_data->if_addr_mask6 && !ifl->ifl_data->if_addr_mask6) {
				int s = strlen(ifl_data->if_addr_mask6);
				ifl->ifl_data->if_addr_mask6 = malloc(s);
				memcpy(ifl->ifl_data->if_addr_mask6, ifl_data->if_addr_mask6, s);
				ifl->ifl_data->if_addr_mask6[s] = '\0';
			}
			
			return;
		} else if (!ifl->ifl_next) {
			ifl->ifl_next = i;
		} else {
			ifl = ifl->ifl_next;
		}
	}
}


int if_name_copy(char *from, char *to)
{
	to = malloc(strlen(from));
	strcpy(to, from);
}

int get_ipv6_mask(char *ipv6_mask)
{
	int n = 0;
	int i = 0;
	int byte4 = 4;
	for (i = 0; ipv6_mask[i]; i++) {
//	while (ipv6_mask) {
		if (ipv6_mask[i] == 'f') {
			n++;
		}
//		ipv6_mask++;
	}
//	printf("f: %d\n", n);
	return n * byte4;
}

/* *** gateway routine *** */

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

int getgateway(struct iface *ifl_data)
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
		
		
		
		struct rtmsg *rt_msg;
		struct rtattr *rt_attr;
		int rt_len = 0;
		
		rt_msg = (struct rtmsg *) NLMSG_DATA(nl_msg);
		
		/* If the route is not for AF_INET or does not belong to main routing table then return. */
		if ((rt_msg->rtm_family != AF_INET) || (rt_msg->rtm_table != RT_TABLE_MAIN)) {
			return;
		}
		printf("LINE: %d\n", __LINE__);
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
					rt_info->dst_addr.s_addr= *(u_int *) RTA_DATA(rt_attr);
					break;
			}
		}
		printf("LINE: %d\n", __LINE__);
		printf("iface for gateway: %s\n", ifl_data->if_name);
		printf("route for gateway: %s\n", rt_info->if_name);
		
		if (strcmp(ifl_data->if_name, rt_info->if_name) == 0) {
			if (rt_info->gateway.s_addr != 0) { // && (ifl_data->if_addr_gateway) && (strcmp(ifl_data->if_addr_gateway, "*\0") == 0)) {
				ifl_data->if_addr_gateway = malloc(512); //strlen((char *) inet_ntoa(rt_info->gateway)));
				memset(ifl_data->if_addr_gateway, '\0', 512);
				strcpy(ifl_data->if_addr_gateway, (char *) inet_ntoa(rt_info->gateway));
			}/* else {
				ifl_data->if_addr_gateway = malloc(3);
				strncpy(ifl_data->if_addr_gateway, "*\0", 2);
			}
			printf("\tip: %s\n", ifl_data->if_addr_gateway);*/
		}
		printf("LINE: %d\n", __LINE__);
		//route_parse(nl_msg, rt_info);
		
		
	}
	
	free(rt_info);
	close(sd);
	
	return 0;
}

/* *** *** *** */

int getnetdeviceinfo(char *if_name)
{
	/*
	struct ifreq    ifr = NULL;
	int sck = socket(PF_INET, SOCK_DGRAM, 0);
	if(sck < 0) {
		perror("socket");
		return 1;
	}
	if(ioctl(sck, SIOCGIFHWADDR, item) < 0) {
		fatal_perror("ioctl(SIOCGIFHWADDR)");
		return 1;
	}
	*/
	
	struct ifreq s;
	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	
	strcpy(s.ifr_name, if_name);
	if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
		int i;
		printf("\thw: ");
		for (i = 0; i < 6; i++) {
			if (i) {
				printf(":");
			}
			printf("%02x", (unsigned char) s.ifr_addr.sa_data[i]);
		}
		printf("\n");
		/* see <linux/if_arp.h> for sa_family link types */
		printf("\ttype: 0x%x [%d]\n", s.ifr_addr.sa_family, s.ifr_addr.sa_family);
	}
	
	return 0;
}

int main(int argc, char *argv[])
{
	
	struct ifaddrs *ifaddr, *ifa;
	int family, s;
	char host[NI_MAXHOST], mask4[NI_MAXHOST], mask6[NI_MAXHOST];
	
	if (getifaddrs(&ifaddr) == -1) {
		perror("getifaddrs");
		exit(EXIT_FAILURE);
	}
	
	struct iface *ifl_data = malloc(sizeof(struct iface));
	ifl_data->if_name = NULL;
	
	struct iface_list *ifl = malloc(sizeof(struct iface_list));
	ifl->ifl_next = NULL;
	ifl->ifl_data = NULL;
	
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL) {
			continue;
		}
		
		ifl->ifl_data = NULL;
		ifl_data->if_addr_ipv4 = NULL;
		ifl_data->if_addr_ipv6 = NULL;
		ifl_data->if_addr_mask4 = NULL;
		ifl_data->if_addr_mask6 = NULL;
		
		//printf(" ==== for ifa_name:: %s\n", ifa->ifa_name);
		
		ifl_data->if_name = ifa->ifa_name;
		
		family = ifa->ifa_addr->sa_family;
		
		if (family == AF_INET) {
			getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
			ifl_data->if_addr_ipv4 = host;
			getnameinfo(ifa->ifa_netmask, sizeof(struct sockaddr_in), mask4, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
			ifl_data->if_addr_mask4 = mask4;
		}
		
		if (family == AF_INET6) {
			void *addr = NULL;
			addr = &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;
			char addrs[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, addr, addrs, INET6_ADDRSTRLEN);
			ifl_data->if_addr_ipv6 = addrs;
			
			void *mask = NULL;
			mask = &((struct sockaddr_in6 *)ifa->ifa_netmask)->sin6_addr;
			char masks[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, mask, masks, INET6_ADDRSTRLEN);
			ifl_data->if_addr_mask6 = masks;
			
//			getnameinfo(ifa->ifa_netmask, sizeof(struct sockaddr_in), mask6, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
			printf("mask6: %s\n", masks);
//			ifl_data->if_addr_mask6 = mask6;
		}
		
		//ifl_add_once(ifl, ifl_data);
		ifl_add_once_ng(ifl, ifl_data);
		
	}
	
	printf(" ==== \n");
	ifl_enum(ifl);
	printf(" ==== \n");
	

	struct iface_list *ifc;
	ifc = NULL;
//	int in = 0;
	for (ifc = ifl->ifl_next; ifc; ifc = ifc->ifl_next) {
//		if (ifc->ifl_data && ifc->ifl_data->if_name) {
			ifc->ifl_data->if_addr_gateway = NULL;
//		printf("if_name: %x\n", &ifc->ifl_data);
//		printf("if_name: %s\n", ifc->ifl_data->if_name);
		getgateway(ifc->ifl_data);
		if (!ifc->ifl_data->if_addr_gateway) {
				ifc->ifl_data->if_addr_gateway = malloc(3);
				strncpy(ifc->ifl_data->if_addr_gateway, "*\0", 2);
//			printf("%s\n", ifc->ifl_data->if_addr_gateway);
//		}
//		}
	}
	}
	
	//struct iface_list *ifc;
	for (ifc = ifl; ifc; ifc = ifc->ifl_next) {
		if (ifc->ifl_data && ifc->ifl_data->if_name) {
			printf("name: %s\n", ifc->ifl_data->if_name);
			getnetdeviceinfo(ifc->ifl_data->if_name);
			printf("\tipv4: %s\n", ifc->ifl_data->if_addr_ipv4);
			printf("\tipv6: %s", ifc->ifl_data->if_addr_ipv6);
			if (ifc->ifl_data->if_addr_mask6) {
				printf("/%d", get_ipv6_mask(ifc->ifl_data->if_addr_mask6));
			}
			printf("\n");
			printf("\tmask4: %s\n", ifc->ifl_data->if_addr_mask4);
			printf("\tmask6: %s\n", ifc->ifl_data->if_addr_mask6);
			if (ifc->ifl_data->if_addr_gateway)
				printf("\tgateway: %s\n", ifc->ifl_data->if_addr_gateway);
		}
	}
	
}

