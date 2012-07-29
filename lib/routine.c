
#include "platform/connect.h"

/*** cross platform routine ***/

/* get sockaddr : IPv4 or IPv6 */
void *get_in_addr(struct sockaddr *sa)
{
	LOG_IN;
	
	if (sa->sa_family == AF_INET) {
		LOG_OUT;
		return &(((struct sockaddr_in *) sa)->sin_addr);
	}
	
	LOG_OUT;
	return &(((struct sockaddr_in6 *) sa)->sin6_addr);
}

/* get sockport : IPv4 or IPv6 */
unsigned int get_in_port(struct sockaddr *sa)
{
	LOG_IN;
	
	if (sa->sa_family == AF_INET) {
		LOG_OUT;
		return (((struct sockaddr_in *) sa)->sin_port);
	}
	
	LOG_OUT;
	return (((struct sockaddr_in6 *) sa)->sin6_port);
}

/* get address from addrinfo as string in addr */
int get_str_addr(struct addrinfo *node, char *addr)
{
	LOG_IN;
	
	/* clean up buffer */
	memset(addr, '\0', INET6_ADDRSTRLEN);
	
#ifdef CNCT_UNIXWARE
	
	/* BSD sockets way */
	
	inet_ntop(node->ai_family, get_in_addr((struct sockaddr *)node->ai_addr), addr, node->ai_addrlen);
	
	/*
	int port_len = 10;
	char port[port_len];
	memset(port, '\0', port_len);
	sprintf(port, ":%u", ntohs(get_in_port((struct sockaddr *)node->ai_addr)));
	printf("port: %s\n", port);
	*/
	
	/*
	if (((struct sockaddr *)node->ai_addr)->sa_family == AF_INET) {
		printf("IPV4\n");
	} else {
		printf("IPV6\n");
	}
	*/
	
#else
	
	/* Winsock way */
	
	#ifdef MINGW
		DWORD len = INET6_ADDRSTRLEN;
		WSAAddressToString((LPSOCKADDR) node->ai_addr, (DWORD) node->ai_addrlen, NULL, addr, &len);
	#else
		InetNtop(node->ai_family, get_in_addr((struct sockaddr *) node->ai_addr), addr, node->ai_addrlen);
	#endif /* MINGW */
	
#endif /* CNCT_UNIXWARE */
	
	LOG_OUT;
	return 0;
}

/* send-whole-buffer routine */
int cnct_socket_sendall(socket_t sd, char *msg, int len, int flags)
{
	LOG_IN;
	
	int r = 0;
	int sended = 0;
	
	while (sended < len) {
		r = send(sd, msg+sended, len, flags);
		if (r == -1) {
			break;
		}
		sended += r;
		len -= r;
	}
	
	LOG_OUT;
	return r == -1 ? -1 : 0;
}

/*** platform related section ***/

#ifdef CNCT_UNIXWARE
	
	/*** BSD stuff ***/
	
#else
	
	/*** Winsock stuff ***/
	
#endif

