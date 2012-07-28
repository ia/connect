
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#ifdef __sunos__
#include <sys/sockio.h>
#endif

#define inaddrr(x) (*(struct in_addr *) &ifr->x[sizeof sa.sin_port])

#if defined(__AIX) || defined(_AIX)
#define MAX(x,y) ((x) > (y) ? (x) : (y))
#define SIZE(p) MAX((p).sa_len, sizeof(p))
#else
#define IFRSIZE ((int)(size * sizeof (struct ifreq)))
#endif


int main ()
{
	unsigned char *u = NULL;
	int sockfd;
	int size = 1;
	struct ifreq *ifr;
	struct ifconf ifc;
	struct sockaddr_in sa;
	struct arpreq arp;
	char macStr[128];

	if (0 > (sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)))
	{
	printf ("Error: Unable to open socket.\n");
	exit (1);
	}

#if defined(__AIX__) || defined(_AIX)
	if (ioctl (sockfd, SIOCGSIZIFCONF, &size) == -1)
	{
	perror("Error getting size of interface :");
	exit (1);
	}

	ifc.ifc_req = (struct ifreq *) malloc (size);
	ifc.ifc_len = size;

	if (ioctl(sockfd, SIOCGIFCONF, &ifc))
	{
	printf ("Error: ioctl SIOCFIFCONF.\n");
	exit (1);
	}
#else
	ifc.ifc_len = IFRSIZE;
	ifc.ifc_req = NULL;

	do
	{
	++size;
	/* realloc buffer size until no overflow occurs */

	if (NULL == (ifc.ifc_req = (struct ifreq*)realloc(ifc.ifc_req, IFRSIZE)))
	{
	printf ("Error: Unable to allocate mememory.\n");
	exit (1);
	}

	ifc.ifc_len = IFRSIZE;
	if (ioctl(sockfd, SIOCGIFCONF, &ifc))
	{
	printf ("Error: ioctl SIOCFIFCONF.\n");
	exit (1);
	}
	} while (IFRSIZE <= ifc.ifc_len);
#endif

	ifr = ifc.ifc_req;

	while ((char *) ifr < (char *) ifc.ifc_req + ifc.ifc_len)
	{
	printf("Interface: %s\n", ifr->ifr_name);
	printf("IP Address: %s\n", inet_ntoa(inaddrr(ifr_addr.sa_data)));


	u = NULL;
#if defined(__linux__) || defined(linux)
	if (0 == ioctl(sockfd, SIOCGIFHWADDR, ifr))
	u = (unsigned char *) &ifr->ifr_addr.sa_data;
	else
	{
#endif

	arp.arp_pa = ifr->ifr_addr;
	if (0 == ioctl (sockfd, SIOCGARP, &arp))
	u = (unsigned char *) arp.arp_ha.sa_data;
	else
	perror ("Error during ioctl");
#if defined(__linux__) || defined(linux)
	}
#endif

	memset (macStr, 0, sizeof (macStr));
	if (u && u[0] + u[1] + u[2] + u[3] + u[4] + u[5])
	{
	sprintf (macStr, "%2.2X-%2.2X-%2.2X-%2.2X-%2.2X-%2.2X", u[0], u[1], u[2], u[3], u[4], u[5]);
	printf ("HW Address: %s", macStr);
	}

	printf("\n");


#if defined(__AIX) || defined(_AIX)
	ifr = ((char *) ifr + sizeof(ifr->ifr_name) + SIZE(ifr->ifr_addr));
#else
	++ifr;
#endif
	}

	close(sockfd);
}
