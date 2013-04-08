
#ifndef _LIBCONNECT_H_
#define _LIBCONNECT_H_

#include "platform/connect.h"

#define CNCT_SOCKET_DATASIZE 4096
#define CNCT_SOCKET_BACKLOG  1024

/* *** connect library custom data types *** */

/* general custom data type for easier usage of cnct_socket_* functions */

struct cnct_socket_struct {
	/* socket_t - socket file descriptor data type */
	socket_t          sd;
	char             *host;
	char             *port;
	int               ipv;
	int               type;
	int               reuse;
	int               autoclose;
	int               flags;
	struct addrinfo  *node;
	char              addr[INET6_ADDRSTRLEN];
	struct sockaddr_storage client;
};

/* structs for union of data buffer and its recv/send length */

struct cnct_socket_data {
	int     len;
	char    data[CNCT_SOCKET_DATASIZE];
};

struct cnct_socket_data_p {
	int      size;
	char    *data;
	int      len;
};

/* aliases to structs */

typedef struct cnct_socket_struct  cnct_socket_t;
typedef struct cnct_socket_data    cnct_sockdata_t;
typedef struct cnct_socket_data_p  cnct_sockdata_p;

/* *** */

/* *** socket routine headers section *** */

/* init routine */

CNCT_EXPORT int cnct_start();
CNCT_EXPORT int cnct_finish();

/* helper routine */

void        *cnct_socket_getaddr     (struct sockaddr *sa);
unsigned int cnct_socket_getport     (struct sockaddr *sa);
int          cnct_socket_getstraddr  (struct addrinfo *node, char *addr);
int          cnct_socket_setnonblock (socket_t sd);

CNCT_EXPORT  int cnct_sockdata_print (char *msg, int size, int len);

/* high level socket functions */

CNCT_EXPORT  cnct_socket_t  *cnct_socket_create   (char *host, char *port, int ipv, int type, int reuse, int autoclose, int flags);
CNCT_EXPORT  cnct_socket_t  *cnct_socket_clone    (cnct_socket_t *sckt_src);
CNCT_EXPORT  int             cnct_socket_delete   (cnct_socket_t *socket);

CNCT_EXPORT  int             cnct_socket_sendmsg  (cnct_socket_t *socket, char *msg, int len);
CNCT_EXPORT  int             cnct_socket_recvmsg  (cnct_socket_t *socket, char *msg, int len);

CNCT_EXPORT  int             cnct_socket_send     (cnct_socket_t *socket, char *msg, int len);
CNCT_EXPORT  int             cnct_socket_recv     (cnct_socket_t *socket, socket_t sd, char *msg, int len);

CNCT_EXPORT  socket_t        cnct_socket_connect  (cnct_socket_t *socket);
CNCT_EXPORT  socket_t        cnct_socket_listen   (cnct_socket_t *socket);
CNCT_EXPORT  socket_t        cnct_socket_accept   (socket_t socket);
CNCT_EXPORT  int             cnct_socket_shutdown (socket_t socket);

CNCT_EXPORT  int             cnct_socket_server   (cnct_socket_t *sckt, int (*callback)(cnct_socket_t *socket, socket_t sd, struct sockaddr_storage, cnct_sockdata_t));

/* high level packet funtions */

/* TODO: split to platform-specific, fix declarations */

CNCT_EXPORT  int             cnct_packet_print    (unsigned char *packet, int proto, ssize_t len);
CNCT_EXPORT  int             cnct_packet_dump     (int engine, char *iface, int proto, char *rule, int (*callback)(unsigned char *packet, int proto, ssize_t len));
CNCT_EXPORT  int             cnct_packet_loop     (int engine, char *iface, int proto, char *rule, int (*callback)(unsigned char *packet, int proto, ssize_t len));
CNCT_EXPORT  socket_t        cnct_packet_open     (int engine,  char *iface, int proto,   char *rule);
CNCT_EXPORT  ssize_t         cnct_packet_recv     (socket_t ps, unsigned char   *packet, size_t len);
CNCT_EXPORT  ssize_t         cnct_packet_send     (socket_t ps, unsigned char   *packet, size_t len, char *iface);
CNCT_EXPORT  int             cnct_packet_close    (socket_t ps);


/* network interfaces functions */


#endif /* _LIBCONNECT_H_ */

