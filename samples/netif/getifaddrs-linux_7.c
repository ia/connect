
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

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
	for (ifc = ifl; ifc; ifc = ifc->ifl_next) {
		if (ifc->ifl_data && ifc->ifl_data->if_name) {
			printf("name: %s\n", ifc->ifl_data->if_name);
			printf("\tipv4: %s\n", ifc->ifl_data->if_addr_ipv4);
			printf("\tipv6: %s", ifc->ifl_data->if_addr_ipv6);
			if (ifc->ifl_data->if_addr_mask6) {
				printf("/%d", get_ipv6_mask(ifc->ifl_data->if_addr_mask6));
			}
			printf("\n");
			printf("\tmask4: %s\n", ifc->ifl_data->if_addr_mask4);
			printf("\tmask6: %s\n", ifc->ifl_data->if_addr_mask6);
		}
	}
	
}

