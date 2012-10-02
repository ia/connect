
#ifndef _API_BSD_H_
#define _API_BSD_H_

/* includes */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <err.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netdb.h>

//#include <linux/if_ether.h>
#include <net/if.h>
//#include <linux/filter.h>

#include <net/ethernet.h>

//#include <linux/in.h>

//int cnct_filter_bpf(char *iface, int rs);

/*
#if ( !defined(CNCT_INCLUDE_PACKET) && ( !defined(CNCT_INCLUDE_SOCKET) ) )
	#error "define packet/socket includes"
#elif ( defined(CNCT_INCLUDE_PACKET) || ( defined(CNCT_INCLUDE_SOCKET) ) )
	#ifdef CNCT_INCLUDE_SOCKET
		#include <arpa/inet.h>
		#include <netinet/in.h>
		#include <netdb.h>
	#endif
	#ifdef CNCT_INCLUDE_PACKET
		#include <linux/in.h>
		#include <linux/if_ether.h>
		#include <net/if.h>
	#endif
#else
	#error "define only one CNC_INCLUDE"
#endif
*/

/* *** */

#endif /* _API_BSD_H_ */

