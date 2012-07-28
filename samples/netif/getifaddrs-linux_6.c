
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
	char *if_addr_ipv4;
	char *if_addr_ipv6;
};

struct iface_list {
	struct iface      *ifl_data;
	struct iface_list *ifl_next;
};

int ifl_enum(struct iface_list *ifl)
{
	printf("ifl_enum: %d\n", __LINE__);
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
	
//	i->ifl_data = ifl_data;
	
	memcpy(i->ifl_data, ifl_data, sizeof(struct iface));
	i->ifl_next = NULL;
	printf("ifl_add: %d: %s\n", __LINE__, ifl_data->if_name);
	
	while (ifl) {
		if (!ifl->ifl_next) {
			//ifl->ifl_data = i->ifl_data;
			ifl->ifl_next = i;
			break;
		} else {
			ifl = ifl->ifl_next;
		}
	}
	
	printf("ifl_add: %d: %s\n", __LINE__, ifl_data->if_name);
	
	return 0;
}

//int ifl_add_once(struct iface_list *ifl, struct iface_list *netif)

int ifl_add_once(struct iface_list *ifl, struct iface *ifl_data)
{
	printf("ifl_add: %d: %s\n", __LINE__, ifl_data->if_name);
	if (strcmp(ifl_data->if_name, "wlan0") == 0) {
		printf("WLAN\n");
	}
	struct iface_list *i;
	i = malloc(sizeof(struct iface_list));
	i->ifl_data = malloc(sizeof(struct iface));
	memcpy(i->ifl_data, ifl_data, sizeof(struct iface));
	i->ifl_next = NULL;
	
	while (ifl) {
//		if (ifl->ifl_data) {
//			printf("--- data:%s\n", ifl->ifl_data->if_name);
//		}
		if (ifl->ifl_data && strcmp(ifl->ifl_data->if_name, ifl_data->if_name) == 0) {
//			printf("--- exist: %s\n", ifl->ifl_data->if_name);
			return;
		} else if (!ifl->ifl_next) {
//			printf("--- add: %s\n", ifl->ifl_data->if_name);
			ifl->ifl_next = i;
		} else {
//			printf("--- next\n");
			ifl = ifl->ifl_next;
		}
	}
}

int ifl_add_once_ng(struct iface_list *ifl, struct iface *ifl_data)
{
	printf("ifl_add: %d: %s\n", __LINE__, ifl_data->if_name);
	printf("ifl_host: %d: %s\n", __LINE__, ifl_data->if_addr_ipv4);
//	if (strcmp(ifl_data->if_name, "wlan0") == 0) {
//		printf("WLAN\n");
//	}
	struct iface_list *i;
	i = malloc(sizeof(struct iface_list));
	i->ifl_data = malloc(sizeof(struct iface));
	memcpy(i->ifl_data, ifl_data, sizeof(struct iface));
/*
	if (ifl_data->if_addr_ipv4) {
		printf("\tipv4: %s\n", ifl_data->if_addr_ipv4);
		i->ifl_data->if_addr_ipv4 = malloc(strlen(ifl_data->if_addr_ipv4));
		memcpy(i->ifl_data->if_addr_ipv4, ifl_data->if_addr_ipv4, strlen(ifl_data->if_addr_ipv4));
	}
*/
	i->ifl_next = NULL;
	
	while (ifl) {
//		if (ifl->ifl_data) {
//			printf("--- data:%s\n", ifl->ifl_data->if_name);
//		}
		if (ifl->ifl_data && strcmp(ifl->ifl_data->if_name, ifl_data->if_name) == 0) {
			
			if (ifl_data->if_addr_ipv4 && !ifl->ifl_data->if_addr_ipv4) {
				int s = strlen(ifl_data->if_addr_ipv4);
				ifl->ifl_data->if_addr_ipv4 = malloc(s);
				memcpy(ifl->ifl_data->if_addr_ipv4, ifl_data->if_addr_ipv4, s);
				ifl->ifl_data->if_addr_ipv4[s] = '\0';
			}

			if (ifl_data->if_addr_ipv6 && !ifl->ifl_data->if_addr_ipv6) {
				printf("IPV6 Address %s\n", ifl_data->if_addr_ipv6);
				int s = strlen(ifl_data->if_addr_ipv6);
				ifl->ifl_data->if_addr_ipv6 = malloc(s+1);
				memset(ifl->ifl_data->if_addr_ipv6, '\0', s+1);
				strncpy(ifl->ifl_data->if_addr_ipv6, ifl_data->if_addr_ipv6, s);
//				memcpy(ifl->ifl_data->if_addr_ipv6, ifl_data->if_addr_ipv6, s);
//				ifl->ifl_data->if_addr_ipv6[s] = '\0';
			}

//			printf("--- exist: %s\n", ifl->ifl_data->if_name);
			return;
		} else if (!ifl->ifl_next) {
//			printf("--- add: %s\n", ifl->ifl_data->if_name);
			ifl->ifl_next = i;
		} else {
//			printf("--- next\n");
			ifl = ifl->ifl_next;
		}
	}
}

/*
int ifaces_add_once(struct ifaces *ifs, struct iface *netif)
{
	while (ifs) {
		if (strcmp(ifs->netif->if_name, netif->if_name) == 0) {
			break;
		} else if (!ifs->next) {
			ifs->next = netif;
		} else {
			ifs = ifs->next;
		}
	}
}
*/

int if_name_copy(char *from, char *to)
{
	to = malloc(strlen(from));
	strcpy(to, from);
}

int main(int argc, char *argv[])
{
	//struct iface ifaces[100] = { 0 };
	
	struct ifaddrs *ifaddr, *ifa;
	int family, s;
	char host[NI_MAXHOST];
	
	if (getifaddrs(&ifaddr) == -1) {
		perror("getifaddrs");
		exit(EXIT_FAILURE);
	}
	
	struct iface *ifl_data = malloc(sizeof(struct iface));
	ifl_data->if_name = NULL;
	
	struct iface_list *ifl = malloc(sizeof(struct iface_list));
	ifl->ifl_next = NULL;
	ifl->ifl_data = NULL; //ifl_data;
	
	int i = 0;
	for (ifa = ifaddr, i = 0; ifa != NULL; ifa = ifa->ifa_next, i++) {
		if (ifa->ifa_addr == NULL) {
			continue;
		}
		
		ifl->ifl_data = NULL;
		ifl_data->if_addr_ipv4 = NULL;
		ifl_data->if_addr_ipv6 = NULL;
		
		printf(" ==== for ifa_name:: %s\n", ifa->ifa_name);
		
		ifl_data->if_name = ifa->ifa_name;
		
		family = ifa->ifa_addr->sa_family;

		if (family == AF_INET) {
			printf("AF_INET\n");
			getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
			printf("HOST: %s\n", host);
			ifl_data->if_addr_ipv4 = host;
			printf("HOST: %s\n", ifl_data->if_addr_ipv4);
		}
		
		if (family == AF_INET6) {

    void * tmpAddrPtr=NULL;
            tmpAddrPtr=&((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;
            char addressBuffer[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, tmpAddrPtr, addressBuffer, INET6_ADDRSTRLEN);
            printf("%s IP Address %s\n", ifa->ifa_name, addressBuffer); 

//			getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in6), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
			ifl_data->if_addr_ipv6 = addressBuffer;
            printf("%s IP Address %s\n", ifa->ifa_name, ifl_data->if_addr_ipv6);
		}
		
//		ifl_add_once(ifl, ifl_data);
		ifl_add_once_ng(ifl, ifl_data);
		
	}
	
	//printf("ifl_name: %s\n", ifl_data->if_name);
	printf(" ==== \n");
	ifl_enum(ifl);
	printf(" ==== \n");
	
//	struct iface *ifl_data = malloc(sizeof(struct iface));
	//ifl_data->if_name = ifa->ifa_name;
	//ifl_add(ifl, ifl_data);

	struct iface_list *ifc;
	for (ifc = ifl; ifc; ifc = ifc->ifl_next) {
		if (ifc->ifl_data && ifc->ifl_data->if_name) {
			printf("name: %s\n", ifc->ifl_data->if_name);
			printf("\tipv4: %s\n", ifc->ifl_data->if_addr_ipv4);
			printf("\tipv6: %s\n", ifc->ifl_data->if_addr_ipv6);
		}
	}

	/*
	struct iface *ifl_data = malloc(sizeof(struct iface));
	ifl_data->if_name = malloc(strlen(ifa->ifa_name));
	strcpy(ifl_data->if_name, ifa->ifa_name);
	ifl->ifl_data = ifl_data;
	ifl_add(ifl, ifl_data);
	ifl_enum(ifl);
	*/
}

