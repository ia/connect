
#ifndef _API_NT_H_
#define _API_NT_H_

/* includes and defines */

#define WIN32_LEAN_AND_MEAN

#if ( ( defined(__MINGW32__) ) || ( defined(__MINGW64__) ) )
	#define _WIN32_WINNT 0x501
	#define  MINGW       1
#else
	#pragma comment(lib, "ws2_32.lib")
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <malloc.h>
#include <errno.h>
#include <sys/types.h>

#ifndef _WIN32_WINNT
	#define _WIN32_WINNT 0x601
#endif

#ifndef __func__
	#define __func__ __FUNCTION__
#endif

#ifndef snprintf
	#define snprintf(fmt, ...) _snprintf(fmt, ##__VA_ARGS__)
#endif

/* custom WIN32 specific data types */
/*
struct thread_data {
	cnct_socket_t *socket;
	socket_t sd;
	int (*cb)(cnct_socket_t *, socket_t);
};
*/


#define    ETH_ALEN          6           /* Octets in one ethernet addr	 */
#define    ETHER_ADDR_LEN    ETH_ALEN    /* Size of ethernet addr */

#ifndef ssize_t
typedef  SSIZE_T  ssize_t;
#endif

#ifndef u_int8_t
typedef  uint8_t  u_int8_t;
#endif

// typedef unsigned char u_int8_t;

/* This is a name for the 48 bit ethernet address available on many systems. */
struct ether_addr {
	u_int8_t  ether_addr_octet[ETH_ALEN];
} /*__attribute__ ((__packed__))*/;


/* 10Mb/s ethernet header */
struct ether_header {
	uint8_t  ether_dhost[ETH_ALEN];  /* destination eth addr */
	uint8_t  ether_shost[ETH_ALEN];  /* source ether addr    */
	uint16_t ether_type;             /* packet type ID field */
} /*__attribute__ ((__packed__))*/;


struct ip {
//#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int   ip_hl:4;  /* header length */
	unsigned int   ip_v:4;   /* version */
//#endif
/*
#if __BYTE_ORDER == __BIG_ENDIAN
	unsigned int ip_v:4;
	unsigned int ip_hl:4;
#endif
*/
	uint8_t        ip_tos;   /* type of service */
	u_short        ip_len;   /* total length */
	u_short        ip_id;    /* identification */
	u_short        ip_off;   /* fragment offset field */
#define IP_RF          0x8000    /* reserved fragment flag */
#define IP_DF          0x4000    /* dont fragment flag */
#define IP_MF          0x2000    /* more fragments flag */
#define IP_OFFMASK     0x1fff    /* mask for fragmenting bits */
	uint8_t        ip_ttl;   /* time to live */
	uint8_t        ip_p;     /* protocol */
	u_short        ip_sum;   /* checksum */
	struct in_addr ip_src;   /* source address */
	struct in_addr ip_dst;   /* dest address */
};


/* custom WIN32 specific functions */
/*
static DWORD WINAPI cnct_socket_request(void *data)
{
	(*((struct thread_data *) data)->cb) (
			(((struct thread_data *) data)->socket),
			(((struct thread_data *) data)->sd)
	);
	return 0;
}
*/


#endif /* _API_NT_H_ */

