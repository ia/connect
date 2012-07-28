#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <net/if_types.h>
#include <errno.h>

/* Print an internet address. */

void
print_ip (const char * name, struct ifaddrs * ifaddrs_ptr, void * addr_ptr)
{
    if (addr_ptr) {
	/* This constant is defined in <netinet/in.h> */
	char address[INET6_ADDRSTRLEN];
	inet_ntop (ifaddrs_ptr->ifa_addr->sa_family,
		   addr_ptr,
		   address, sizeof (address));
	printf ("%s: %s\n", name, address);
    } else {
	printf ("No %s\n", name);
    }
}

/* Get a pointer to the address structure from a sockaddr. */

void *
get_addr_ptr (struct sockaddr * sockaddr_ptr)
{
    void * addr_ptr = 0;
    if (sockaddr_ptr->sa_family == AF_INET)
        addr_ptr = &((struct sockaddr_in *)  sockaddr_ptr)->sin_addr;
    else if (sockaddr_ptr->sa_family == AF_INET6)
        addr_ptr = &((struct sockaddr_in6 *) sockaddr_ptr)->sin6_addr;
    return addr_ptr;
}

/* Print the internet address. */

void
print_internet_address (struct ifaddrs * ifaddrs_ptr)
{
    void * addr_ptr;
    if (! ifaddrs_ptr->ifa_addr)
	return;
    addr_ptr = get_addr_ptr (ifaddrs_ptr->ifa_addr);
    print_ip ("internet address", ifaddrs_ptr, addr_ptr);
}

/* Print the netmask. */

void
print_netmask (struct ifaddrs * ifaddrs_ptr)
{
    void * addr_ptr;
    if (! ifaddrs_ptr->ifa_netmask)
	return;
    addr_ptr = get_addr_ptr (ifaddrs_ptr->ifa_netmask);
    print_ip ("netmask", ifaddrs_ptr, addr_ptr);
}

/* Print the mac address. */

void
print_mac_address (const char * mac_address)
{
    int mac_addr_offset;
    printf ("Mac address: ");
    for (mac_addr_offset = 0; mac_addr_offset < 6; mac_addr_offset++) {
	printf ("%02x", (unsigned char) mac_address[mac_addr_offset]);
	if (mac_addr_offset != 5)
	    printf (":");
    }
    printf ("\n");
}

/* Adapted from http://othermark.livejournal.com/3005.html */

void
print_af_link (struct ifaddrs * ifaddrs_ptr)
{
    struct sockaddr_dl * sdl;
    sdl = (struct sockaddr_dl *) ifaddrs_ptr->ifa_addr;
    /* These types are defined in <net/iftypes.h>. */
    if (sdl->sdl_type == IFT_ETHER) {
	print_mac_address (LLADDR (sdl));
    } else if (sdl->sdl_type == IFT_LOOP) {
	printf ("Loopback.\n");
    } else {
	printf ("Link of type %d\n", sdl->sdl_type);
    }
}

void
print_internet_interface (struct ifaddrs * ifaddrs_ptr)
{
    print_internet_address (ifaddrs_ptr);
    print_netmask (ifaddrs_ptr);
    if (ifaddrs_ptr->ifa_dstaddr) {
	void * addr_ptr = get_addr_ptr (ifaddrs_ptr->ifa_dstaddr);
	print_ip ("destination", ifaddrs_ptr, addr_ptr);
    }
    if (ifaddrs_ptr->ifa_broadaddr) {
	void * addr_ptr = get_addr_ptr (ifaddrs_ptr->ifa_broadaddr);
	print_ip ("broadcast", ifaddrs_ptr, addr_ptr);
    }
}

/* Adapted from
   http://publib.boulder.ibm.com/infocenter/iseries/v6r1m0/index.jsp?topic=/apis/getifaddrs.htm */


void
print_ifaddrs (struct ifaddrs * ifaddrs_ptr)
{
    struct ifaddrs * ifa_next;

    /* Print this one. */
    printf ("Name: %s flags: %x\n",
	    ifaddrs_ptr->ifa_name, ifaddrs_ptr->ifa_flags);
    if (ifaddrs_ptr->ifa_addr->sa_family == AF_INET) {
    /* AF_INET is defined in /usr/include/sys/socket.h. */

	printf ("AF_INET\n");
	print_internet_interface (ifaddrs_ptr);
    } else if (ifaddrs_ptr->ifa_addr->sa_family == AF_INET6) {
	printf ("AF_INET6\n");
	print_internet_interface (ifaddrs_ptr);
    } else if (ifaddrs_ptr->ifa_addr->sa_family == AF_LINK) {
	printf ("AF_LINK\n");
	print_af_link (ifaddrs_ptr);
    }
    /* Do the next one. */
    ifa_next = ifaddrs_ptr->ifa_next;
    if (!ifa_next)
	return;
    print_ifaddrs (ifa_next);
}

int main ()
{
    struct ifaddrs * ifaddrs_ptr;
    int status;
    status = getifaddrs (& ifaddrs_ptr);
    if (status == -1) {
	fprintf (stderr, "Error in 'getifaddrs': %d (%s)\n",
		 errno, strerror (errno));
	exit (1);
    }
    print_ifaddrs (ifaddrs_ptr);
    freeifaddrs (ifaddrs_ptr);
    return 0;
}
