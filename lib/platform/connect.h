
#ifndef _PLATFORM_H_
#define _PLATFORM_H_

#ifndef BUILDREV
#define BUILDREV 0
#endif

#if ( defined(__unix__) || ( defined(__APPLE__) && defined(__MACH__) ) )
	
	/* BSD sockets API conventions */
	
	#define CNCT_UNIXWARE 1
	#define SOCKET_STYLE "BSD"
	#define socket_t int
	#define cnct_socket_close(socket_t) close(socket_t)
	#define EXPORT
	
#elif ( defined(_WIN32) || defined(_WIN64) )
	
	/* Winsock sockets API conventions */
	
	#define CNCT_WINSWARE 1
	#define SOCKET_STYLE "WIN"
	#define socket_t SOCKET
	#define cnct_socket_close(socket_t) closesocket(socket_t)
	#define EXPORT __declspec(dllexport)
	#define __func__ __FUNCTION__
	
#else
	
	#error "Current platform not supported"
	
#endif

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

#define MALLOC_PNTR_TYPE(type, var) \
	var = (type *) malloc(sizeof(type)); if (!var) { printf("malloc error\n"); } else { memset(var, '\0', sizeof(type)); }

#define FREE_PNTR(ptr) \
	if (ptr) { free(ptr); }

#define IF_NOT_NULL(ptr, action) \
	if (ptr) { action; }

/* TODO: CNCT_GETADDRINFO macro */

#define CNCT_SOCKET_INIT(socket) \
	socket->sd = -1; socket->type = type; socket->flags = flags;

/* includes */

#ifdef CNCT_UNIXWARE
	#include "api_bsd.h"
#else
	#include "api_nt.h"
#endif

#include "../routine.h"

#define CNCT_TCP SOCK_STREAM
#define CNCT_UDP SOCK_DGRAM

/* data types */

struct cnct_socket_struct {
	socket_t          sd;
	char             *host;
	char             *port;
	int               type;
	int               reuse;
	int               autoclose;
	int               flags;
	struct addrinfo  *node;
	char              addr[INET6_ADDRSTRLEN];
};

typedef struct cnct_socket_struct cnct_socket_t;

#define cnct_socket_init(cnct_socket_t)  cnct_socket_t.sd = -1; cnct_socket_t.host = NULL; cnct_socket_t.port = NULL;

#endif /* _PLATFORM_H_ */

