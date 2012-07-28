
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/ioctl.h>

#ifndef SIOCGIFCONF
	#include <sys/sockio.h>
#endif

#include <netinet/in.h>
#include <net/if.h>
#include <netinet/if_ether.h>

#ifdef OSIOCGIFCONF
	#undef SIOCGIFCONF
	#define SIOCGIFCONF OSIOCGIFCONF
	#undef SIOCGIFADDR
	#define SIOCGIFADDR OSIOCGIFADDR
	#undef SIOCGIFBRDADDR
	#define SIOCGIFBRDADDR OSIOCGIFBRDADDR
#endif

#define fatal_perror(X) do { perror(X), exit(1); } while(0)

/*
 * this is straight from beej's network tutorial. It is a nice wrapper
 * for inet_ntop and helpes to make the program IPv6 ready
 */

char *get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen)
{
	switch(sa->sa_family) {
		case AF_INET:
			inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr), s, maxlen);
			break;
		case AF_INET6:
			inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr), s, maxlen);
			break;
		default:
			strncpy(s, "Unknown AF", maxlen);
			return NULL;
	}
	
	return s;
}

int main(int argc, char const* argv[])
{
	char            buf[8192] = {0};
	struct ifconf   ifc = {0};
	struct ifreq   *ifr = NULL;
	int             sck = 0;
	int             nInterfaces = 0;
	int             i = 0;
	char            ip[INET6_ADDRSTRLEN] = {0};
	struct ifreq    *item;
	struct sockaddr *addr;
	socklen_t       salen;
	char            hostname[NI_MAXHOST];
	
	/* Get a socket handle. */
	sck = socket(PF_INET, SOCK_DGRAM, 0);
	if(sck < 0) {
		fatal_perror("socket");
		return 1;
	}
	
	/* Query available interfaces. */
	ifc.ifc_len = sizeof(buf);
	ifc.ifc_buf = buf;
	if(ioctl(sck, SIOCGIFCONF, &ifc) < 0) {
		fatal_perror("ioctl(SIOCGIFCONF)");
		return 1;
	}
	
	/* Iterate through the list of interfaces. */
	ifr = ifc.ifc_req;
	nInterfaces = ifc.ifc_len / sizeof(struct ifreq);
	for(i = 0; i < nInterfaces; i++) {
		bzero(hostname, NI_MAXHOST);
		item = &ifr[i];
		
		/* Show the device name and IP address */
		addr = &(item->ifr_addr);
		
		switch(addr->sa_family) {
			case AF_INET:
				salen = sizeof(struct sockaddr_in);
				break;
			case AF_INET6:
				salen = sizeof(struct sockaddr_in6);
				break;
			default:
				salen = 0;
				break;
		}
		
		/* the call to get the mac address changes what is stored in the
		item, meaning that we need to determine the hostname now */
		getnameinfo(addr, salen, hostname, sizeof(hostname), NULL, 0, NI_NAMEREQD);
		
		/* Get the address
		 * This may seem silly but it seems to be needed on some systems
		 */
		if(ioctl(sck, SIOCGIFADDR, item) < 0) {
			fatal_perror("ioctl(OSIOCGIFADDR)");
		}
		
		printf("%s %s", item->ifr_name, get_ip_str(addr, ip, INET6_ADDRSTRLEN));
		
		/* Get the MAC address */
		if(ioctl(sck, SIOCGIFHWADDR, item) < 0) {
			fatal_perror("ioctl(SIOCGIFHWADDR)");
			return 1;
		}
		
		/* display result */
		printf(" %02x:%02x:%02x:%02x:%02x:%02x",
			(unsigned char)item->ifr_hwaddr.sa_data[0],
			(unsigned char)item->ifr_hwaddr.sa_data[1],
			(unsigned char)item->ifr_hwaddr.sa_data[2],
			(unsigned char)item->ifr_hwaddr.sa_data[3],
			(unsigned char)item->ifr_hwaddr.sa_data[4],
			(unsigned char)item->ifr_hwaddr.sa_data[5]);
			
		printf(" %s\n", hostname);
		
	}
	
	return 0;
}

