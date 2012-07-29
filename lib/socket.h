
#include "platform/connect.h"

#define BREAK 1
#define MAXDATASIZE 32*1024
#define BACKLOG 10

/* TODO */
/*



*/


/* current */

EXPORT int tcp_sendmsg_legacy(const char *host_id, const char *port, char *msg, int len, int flags);
EXPORT int tcp_sendmsg(const char *host_id, const char *port, char *msg, int len, int flags);

EXPORT socket_t tcp_connect(const char *host_id, const char *port, struct addrinfo *hints);

EXPORT cnct_socket_t *cnct_socket_create(char *host, char *port, int type, int reuse, int autoclose, int flags);

EXPORT socket_t cnct_socket_connect(cnct_socket_t *socket);

EXPORT int cnct_socket_sendmsg(cnct_socket_t *socket, char *msg, int len);

EXPORT int cnct_socket_recvmsg(cnct_socket_t *socket, char *msg);
EXPORT int cnct_socket_recvmsg_(cnct_socket_t *socket, char *msg);

EXPORT int cnct_socket_server(cnct_socket_t *sckt, int (*callback)(socket_t socket));

//EXPORT socket_t cnct_socket_bind(cnct_socket_t *sckt);
EXPORT socket_t cnct_socket_listen(cnct_socket_t *socket);
EXPORT socket_t cnct_socket_accept(cnct_socket_t *socket);

EXPORT int cnct_socket_delete(cnct_socket_t *socket);

EXPORT int cnct_socket_recvmsg_msdn(cnct_socket_t *sckt, char *msg);

/* old design */
/*
EXPORT int tcp_sendmsg(const char *host_id, const char *port, char *msg, int size, int flags);
int tcp_recvmsg(const char *port, char *msg);

socket_t tcp_connect(const char *host_id, const char *port);
socket_t tcp_accept(const char *port);

int tcp_send(socket_t sd, char *msg, int len, int flags);
int tcp_recv(socket_t sd, char *msg, int len, int flags);

int tcp_disconnect(socket_t sd);
*/

