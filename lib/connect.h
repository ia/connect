
#ifndef _LIBCONNECT_H_
#define _LIBCONNECT_H_

#include "platform/connect.h"

/* *** connect library custom data types *** */

/* socket_t - socket file descriptor data type */

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

/* *** */

/* *** socket routine headers section *** */

/* TODO: clean up */
#define BREAK 1
#define MAXDATASIZE 32*1024
#define BACKLOG 10

CNCT_EXPORT int cnct_start();
CNCT_EXPORT int cnct_finish();

void        *cnct_socket_getaddr     (struct sockaddr *sa);
unsigned int cnct_socket_getport     (struct sockaddr *sa);
int          cnct_socket_getstraddr  (struct addrinfo *node, char *addr);
int          cnct_socket_setnonblock (socket_t sd);

CNCT_EXPORT cnct_socket_t *cnct_socket_create(char *host, char *port, int type, int reuse, int autoclose, int flags);

CNCT_EXPORT socket_t cnct_socket_connect(cnct_socket_t *socket);

CNCT_EXPORT int cnct_socket_sendmsg(cnct_socket_t *socket, char *msg, int len);

CNCT_EXPORT int cnct_socket_recvmsg(cnct_socket_t *socket, char *msg);
CNCT_EXPORT int cnct_socket_recvmsg_(cnct_socket_t *socket, char *msg);

CNCT_EXPORT int cnct_socket_server(cnct_socket_t *sckt, int (*callback)(socket_t socket));

CNCT_EXPORT socket_t cnct_socket_listen(cnct_socket_t *socket);
CNCT_EXPORT socket_t cnct_socket_accept(cnct_socket_t *socket);

CNCT_EXPORT int cnct_socket_delete(cnct_socket_t *socket);

CNCT_EXPORT int cnct_socket_recvmsg_msdn(cnct_socket_t *sckt, char *msg);

#endif /* _LIBCONNECT_H_ */

