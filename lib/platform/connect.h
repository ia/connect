
#ifndef _PLATFORM_H_
#define _PLATFORM_H_

#ifndef CNCT_BUILDREV
#define CNCT_BUILDREV 0
#endif

/* detect platform for sockets style type */
/*
#define CNCT_UNIXWARE_VALUE 1
#define CNCT_WINSWARE_VALUE 2
*/
#define CNCT_API_BSD_TYPE   1
#define CNCT_API_NT_TYPE    2

#define CNCT_SYS_LINUX_T   11
#define CNCT_SYS_BSD_T     12
#define CNCT_SYS_OSX_T     13
#define CNCT_SYS_NT_T      14

#if ( defined(__unix__) || ( defined(__APPLE__) && defined(__MACH__) ) || ( defined(__QNX__) ) )
	
	/* BSD sockets API conventions */
	
	#define CNCT_API_BSD                 CNCT_API_BSD_TYPE
	#define CNCT_SOCKETS                 "BSD"
	#define socket_t                     int
	#define cnct_socket_close(socket_t)  close(socket_t)
	#define CNCT_SHUTDOWN_RX             SHUT_RD
	#define CNCT_SHUTDOWN_TX             SHUT_WR
	#define CNCT_SHUTDOWN_DUPLEX         SHUT_RDWR
	#define CNCT_EXPORT
	#define CNCT_ERROR                   -1
	#define CNCT_INVALID                 -1
	//#define CNCT_SOCKET_RAW              PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)
	
#elif ( defined(_WIN32) || defined(_WIN64) )
	
	/* Winsock sockets API conventions */
	
	#define CNCT_API_NT                  CNCT_API_NT_TYPE
	#define CNCT_SOCKETS                 "WIN"
	#define socket_t                     SOCKET
	#define cnct_socket_close(socket_t)  closesocket(socket_t)
	#define CNCT_SHUTDOWN_RX             SD_RECEIVE
	#define CNCT_SHUTDOWN_TX             SD_SEND
	#define CNCT_SHUTDOWN_DUPLEX         SD_BOTH
	#define CNCT_EXPORT                  __declspec(dllexport)
	#define CNCT_ERROR                   SOCKET_ERROR
	#define CNCT_INVALID                 INVALID_SOCKET
	#define CNCT_SOCKET_RAW              AF_INET, SOCK_RAW, IPPROTO_RAW
	
#else
	
	#error "Current platform not supported"
	
#endif

#define cnct_socket_raw() socket(CNCT_SOCKET_RAW)

#ifndef RELEASE
	
	/* helper defines for debugging info output */
	
	#define DEBUG 1
	#define DBG_ON(action) \
		action
	#define DBG_INFO(action) \
		printf("%s: %s: %d: ", __FILE__, __func__, __LINE__); action
	#define DBG_PRINT(fmt, ...) printf(fmt ##__VA_ARGS__)
	#define LOG_IN \
		printf(" ==== >>>> %s: %s: %d\n", __FILE__, __func__, __LINE__);
	#define LOG_OUT \
		printf(" <<<< ==== %s: %s: %d\n", __FILE__, __func__, __LINE__);
	#define LOG_OUT_RET(r) \
		printf(" <<<< ==== %s: %s: %d\n", __FILE__, __func__, __LINE__); return r;
	#define PRINT_L(value) \
		printf("\t" #value " = %ld\n", value);
	#define PRINT_S(value) \
		printf("\t" #value " = %s\n", value);
	#define PRINT_D(value) \
		printf("\t" #value " = %d\n", value);
	
#elif defined RELEASE
	
	/* disable debug helper defines in RELEASE version */
	
	#undef DEBUG
	#define DBG_ON
	#define DBG_INFO
	#define DBG_PRINT
	#define LOG_IN
	#define LOG_OUT
	#define LOG_OUT_RET(r) return r;
	#define PRINT_L
	#define PRINT_S
	#define PRINT_D
	
#endif

/* generic routine helper defines */

#define RET_ON_NULL(ptr, msg) \
	if (!ptr) { fprintf(stderr, "%s\n", msg); return 1; }

#define RET_ON_NULL_INFO(ptr, msg) \
	if (!ptr) { fprintf(stderr, "%s: %s: %d: %s\n", __FILE__, __func__, __LINE__, msg); return 1; }

#define EXIT_ON_NULL(ptr, msg) \
	if (!ptr) { fprintf(stderr, "%s\n", msg); exit 1; }

#define EXIT_ON_NULL_INFO(ptr, msg) \
	if (!ptr) { fprintf(stderr, "%s: %s: %d: %s\n", __FILE__, __func__, __LINE__, msg); exit 1; }

#define MALLOC_TYPE(type, var) \
	type *var = (type *) malloc(sizeof(type)); if (!var) { printf("malloc error\n"); } else { memset(var, '\0', sizeof(type)); }

#define MALLOC_PNTR(var, size) \
	var = malloc(size); if (!var) { printf("malloc error\n"); } else { memset(var, '\0', size); }

#define MALLOC_PNTR_SIZE(type, var, size) \
	var = (type *) malloc(size); if (!var) { printf("malloc error\n"); } else { memset(var, '\0', size); }

#define MALLOC_TYPE_SIZE(type, var, size) \
	type *var = (type *) malloc(size); if (!var) { printf("malloc error\n"); } else { memset(var, '\0', size); }

#define MALLOC_PNTR_TYPE(type, var) \
	var = (type *) malloc(sizeof(type)); if (!var) { printf("malloc error\n"); } else { memset(var, '\0', sizeof(type)); }

#define FREE_PNTR(ptr) \
	if (ptr) { free(ptr); }

#define IF_NULL(ptr, action) \
	if (!ptr) { action; }

#define IF_NOT_NULL(ptr, action) \
	if (ptr) { action; }

#define SET_VALUE(var, cmp, val, def) \
	(((cmp == val) || (cmp == def)) ? (var = cmp) : (var = def));

/* TODO: CNCT_GETADDRINFO macro */

#define CNCT_TCP SOCK_STREAM
#define CNCT_UDP SOCK_DGRAM

#define CNCT_SEND(socket, data, ptr, len, ret) \
	if (socket->type == SOCK_STREAM) \
		{ ret = send  (socket->sd, data + ptr, len, socket->flags); } \
	else    { ret = sendto(socket->sd, data + ptr, len, socket->flags, socket->node->ai_addr, socket->node->ai_addrlen); }

#define CNCT_RECV(socket, sd, data, ptr, len, ret) \
	if (socket->type == SOCK_STREAM) \
		{ ret = recv    (sd, data + ptr, len, socket->flags); } \
	else    { \
		  socklen_t slen = sizeof(struct sockaddr_storage); \
		  ret = recvfrom(sd, data + ptr, len, socket->flags, (struct sockaddr *) &(socket->client), (socklen_t *) &slen); \
	}

#define MALLOC_SOCKDATA(ptr, s) \
	MALLOC_TYPE(cnct_sockdata_p, ptr) \
	MALLOC_PNTR_SIZE(char, ptr->data, s) \
	ptr->size = s; ptr->len  = 0;

#define CNCT_PACKENGINE_SET 0x0
#define CNCT_PACKENGINE_USR 0x1
#define CNCT_PACKENGINE_BPF 0x2
#define CNCT_PACKENGINE_PCP 0x3

#define CNCT_BPF_PCKT { 0x6, 0, 0, 0x0000ffff }

/* TODO: fix and test this section for correct defines */
#if ( defined(SYS_LINUX) || defined(__linux__) )
	#define  CNCT_SYS_LINUX CNCT_SYS_LINUX_T
	#define  CNCT_SYS       CNCT_SYS_LINUX
	#warning "TARGET: CNCT_SYS_LINUX"
//	#include <linux/filter.h>
	#define CNCT_SOCKET_RAW    PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)
	#define CNCT_SOCKET_IP     PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)
	#define cnct_mtu  1024 * 64
	//#include "sys_linux.h"
#elif ( defined(SYS_BSD) || ( (!defined(__linux__)) && defined(__unix__) ) || ( defined(__APPLE__) && defined(__MACH__) ) )
	#define  CNCT_SYS_BSD   CNCT_SYS_BSD_T
	#define  CNCT_SYS       CNCT_SYS_BSD
//	#include <net/bpf.h>
	#warning "TARGET: CNCT_SYS_BSD"
	//#include "sys_bsd.h"
	#define cnct_mtu  1024 *  4
/*
#elif ( defined(SYS_OSX) || ( defined(__APPLE__) && defined(__MACH__) ) )
	#define  CNCT_SYS_OSX   CNCT_SYS_OSX_T
	#define  CNCT_SYS       CNCT_SYS_OSX
	#include <net/bpf.h>
	#warning "TARGET: CNCT_SYS_OSX"
	//#include "sys_osx.h"
*/
#elif ( defined(SYS_NT) || defined(_WIN32) || defined(_WIN64) )
	#define  CNCT_SYS_NT    CNCT_SYS_NT_T
	#define  CNCT_SYS       CNCT_SYS_NT
	#pragma message("TARGET: CNCT_SYS_NT")
	//#include "sys_nt.h"
#else
	#error "define SYS_NAME manually"
#endif

/* includes */

#ifdef CNCT_API_BSD
	#define  CNCT_API CNCT_API_BSD
	#include "api_bsd.h"
#else
	#define  CNCT_API CNCT_API_NT
	#include "api_nt.h"
#endif

#ifndef CNCT_SOCKET_RAW
	#define CNCT_SOCKET_RAW    AF_INET, SOCK_RAW, IPPROTO_RAW
#endif

#ifndef CNCT_SOCKET_IP
	#define CNCT_SOCKET_IP    AF_INET, SOCK_RAW, IPPROTO_IP
#endif

/* *** */

static const int cnct_api = CNCT_API;
static const int cnct_sys = CNCT_SYS;

/* export, but not for external usage */
CNCT_EXPORT  int cnct_filter_bpf (char *iface, socket_t sd);

#endif /* _PLATFORM_H_ */

