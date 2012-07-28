
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

struct iface {
	char *if_name;
	struct sockaddr *if_addr_ipv4;
	struct sockaddr *if_addr_ipv6;
};

struct iface_list {
	struct iface      *ifl_data;
	struct iface_list *ifl_next;
};

int ifl_enum(struct iface_list *ifl)
{
	printf("ifl_enum: %d\n", __LINE__);
	while (ifl) {
		printf("%d\n", __LINE__);
		if (ifl->ifl_data) {
			printf("iface->if_name: %s\n", ifl->ifl_data->if_name);
		}
		printf("%d\n", __LINE__);
		ifl = ifl->ifl_next;
		printf("%d\n", __LINE__);
	}
	printf("%d\n", __LINE__);
}

int ifl_add(struct iface_list *ifl, struct iface *ifl_data)
{
	printf("%d\n", __LINE__);
	struct iface_list *i;
	i = malloc(sizeof(struct iface_list));
	i->ifl_next = NULL;
	i->ifl_data = ifl_data;
	printf("%d\n", __LINE__);
	while (ifl) {
	printf("%d\n", __LINE__);
		if (!ifl->ifl_next) {
	printf("%d\n", __LINE__);
			ifl->ifl_next = i;
			break;
		} else {
	printf("%d\n", __LINE__);
			ifl = ifl->ifl_next;
		}
	printf("%d\n", __LINE__);
	}
	printf("%d\n", __LINE__);
}

//int ifl_add_once(struct iface_list *ifl, struct iface_list *netif)
/*
int ifl_add_once(struct iface_list *ifl, struct iface_list *netif)
{
	while (ifl) {
		if (strcmp(ifl->ifl_data->if_name, netif->netif->if_name) == 0) {
			break;
		} else if (!ifl->ifl_next) {
			ifl->ifl_next = ifl_data;
		} else {
			ifl = ifl->ifl_next;
		}
	}
}
*/

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
	
	int i = 0;
	for (ifa = ifaddr, i = 0; ifa != NULL; ifa = ifa->ifa_next, i++) {
		if (ifa->ifa_addr == NULL) {
			continue;
		}
		
		printf("%s\n", ifa->ifa_name);
		
		
		
		break;
		
	}
	
	printf("ifa_name: %s\n", ifa->ifa_name);
	//printf("ifl_name: %s\n", ifl_data->if_name);
	
	struct iface_list *ifl = malloc(sizeof(struct iface_list));
	ifl->ifl_next = NULL;
	ifl->ifl_data = NULL;
	
	ifl_enum(ifl);
	
	struct iface *ifl_data = malloc(sizeof(struct iface));
	ifl_data->if_name = ifa->ifa_name;
//	ifl->ifl_data = ifl_data;
	ifl_add(ifl, ifl_data);
	ifl_enum(ifl);


	/*
	struct iface *ifl_data = malloc(sizeof(struct iface));
	ifl_data->if_name = malloc(strlen(ifa->ifa_name));
	strcpy(ifl_data->if_name, ifa->ifa_name);
	ifl->ifl_data = ifl_data;
	ifl_add(ifl, ifl_data);
	ifl_enum(ifl);
	*/
}

