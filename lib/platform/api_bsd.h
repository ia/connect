
#ifndef _API_BSD_H_
#define _API_BSD_H_

#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif

/* includes */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <err.h>
#include <signal.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netdb.h>

//#include <linux/if_ether.h>
#include <net/if.h>
//#include <linux/filter.h>

//#include <net/bpf.h>

#include <netinet/ip.h>

#ifdef __QNX__

#include <io-pkt/sys/types_bsd.h>
#include <sys/io-pkt.h>
#include <sys/syspage.h>
#include <sys/device.h>
#include <device_qnx.h>
#include <net/if_ether.h>
#include <net/if_media.h>
#include <net/netbyte.h>
#include <net80211/ieee80211_var.h>

#else

#include <net/ethernet.h>

#endif

#ifdef CNCT_SYS_LINUX
	#include <linux/filter.h>
	#include <linux/if_packet.h>
	#include <linux/if_ether.h>
//	#include <linux/if_arp.h>
#endif

#ifdef CNCT_SYS_BSD
	#include <net/bpf.h>
#endif

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

