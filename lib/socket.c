
#include "connect.h"

/*
 * TODO:
 *
 *  - LOG_OUT_RET
 *  - each error processing
 *  - wrap server routine in macros/headers/defines/funcs
 *  - add UDP support for listen/accept/recv
 *  - char *msg -> void *data
 *  - len for recv
 *  - clean up release/debug output
 *
 */

/* for Windows platform - init WinSock layer */
int cnct_start()
{
	LOG_IN;
	
#ifdef CNCT_WINSWARE
	
	WORD wsa_version;
	WSADATA wsa_data;
	int r;
	
	wsa_version = MAKEWORD(2, 2);
	
	r = WSAStartup(wsa_version, &wsa_data);
	if (r != 0) {
		printf("WSAStartup failed with error: %d\n", r);
		return r;
	}
	
	if (LOBYTE(wsa_data.wVersion) != 2 || HIBYTE(wsa_data.wVersion) != 2) {
		printf("Could not find a usable version of Winsock.dll\n");
		WSACleanup();
		return 1;
	} else {
		printf("The Winsock 2.2 dll was found okay\n");
	}
	
	DBG_ON(printf("_WIN32_WINNT: 0x%x\n", _WIN32_WINNT));
	
#endif /* CNCT_WINSWARE */
	
	DBG_ON(printf("build revision: %d\n", CNCT_BUILDREV));
	
	LOG_OUT;
	
	return 0;
}

/* for Windows platform - clean up WinSock layer */
int cnct_finish()
{
	LOG_IN;
	
#ifdef CNCT_WINSWARE
	
	WSACleanup();
	
#endif /* CNCT_WINSWARE */
	
	LOG_OUT;
	
	return 0;
}

/* get sockaddr : IPv4 or IPv6 */
void *cnct_socket_getaddr(struct sockaddr *sa)
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
unsigned int cnct_socket_getport(struct sockaddr *sa)
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
int cnct_socket_getstraddr(struct addrinfo *node, char *addr)
{
	LOG_IN;
	
	/* clean up buffer */
	memset(addr, '\0', INET6_ADDRSTRLEN);
	
#ifdef CNCT_UNIXWARE
	
	inet_ntop(node->ai_family, cnct_socket_getaddr((struct sockaddr *)node->ai_addr), addr, node->ai_addrlen);
	
#else
	
	#ifdef MINGW
		DWORD len = INET6_ADDRSTRLEN;
		WSAAddressToString((LPSOCKADDR) node->ai_addr, (DWORD) node->ai_addrlen, NULL, addr, &len);
	#else
		InetNtop(node->ai_family, cnct_socket_getaddr((struct sockaddr *) node->ai_addr), addr, node->ai_addrlen);
	#endif /* MINGW */
	
#endif /* CNCT_UNIXWARE */
	
	LOG_OUT;
	
	return 0;
}

/* set socket to non-blocking state */
int cnct_socket_setnonblock(socket_t sd)
{
	LOG_IN;
	
#ifdef CNCT_UNIXWARE
	
	int flags, s;
	
	flags = fcntl(sd, F_GETFL, 0);
	if (flags == -1) {
		perror("fcntl");
		return -1;
	}
	
	flags |= O_NONBLOCK;
	s = fcntl(sd, F_SETFL, flags);
	if (s == -1) {
		perror("fcntl");
		return -1;
	}
	
#endif /* CNCT_UNIXWARE */
	
	LOG_OUT;
	
	return 0;
}

/* create socket struct routine */
cnct_socket_t *cnct_socket_create(char *host, char *port, int type, int reuse, int autoclose, int flags)
{
	LOG_IN;
	
	MALLOC_TYPE(cnct_socket_t, socket);
	
	IF_NOT_NULL(host, MALLOC_PNTR_SIZE(char, socket->host, strlen(host)); strcpy(socket->host, host));
	IF_NOT_NULL(port, MALLOC_PNTR_SIZE(char, socket->port, strlen(port)); strcpy(socket->port, port));
	
	socket->sd = -1;
	socket->type = type;
	socket->reuse = reuse;
	socket->autoclose = autoclose;
	socket->flags = flags;
	socket->node = NULL;
	
	LOG_OUT;
	
	return socket;
}

/* clone socket struct routine */
cnct_socket_t *cnct_socket_clone(cnct_socket_t *sckt_src)
{
	LOG_IN;
	
	MALLOC_TYPE(cnct_socket_t, sckt_dst);
	
	IF_NOT_NULL(sckt_src->host, MALLOC_PNTR_SIZE(char, sckt_dst->host, strlen(sckt_src->host)); strcpy(sckt_dst->host, sckt_src->host));
	IF_NOT_NULL(sckt_src->port, MALLOC_PNTR_SIZE(char, sckt_dst->port, strlen(sckt_src->port)); strcpy(sckt_dst->port, sckt_src->port));
	
	IF_NOT_NULL(sckt_src->node, MALLOC_PNTR_TYPE(struct addrinfo, sckt_dst->node); memcpy(sckt_dst->node, sckt_src->node, sizeof(struct addrinfo)));
	
	sckt_dst->sd        = sckt_src->sd;
	sckt_dst->type      = sckt_src->type;
	sckt_dst->reuse     = sckt_src->reuse;
	sckt_dst->autoclose = sckt_src->autoclose;
	sckt_dst->flags     = sckt_src->flags;
	sckt_dst->node      = NULL;
	
	LOG_OUT;
	
	return sckt_dst;
}

/* delete socket struct routine */
int cnct_socket_delete(cnct_socket_t *socket)
{
	LOG_IN;
	
	if (socket) {
		FREE_PNTR(socket->host);
		FREE_PNTR(socket->port);
		FREE_PNTR(socket->node);
		
		//cnct_socket_close(socket->sd);
		cnct_socket_shutdown(socket->sd);
		
		free(socket);
	}
	
	LOG_OUT;
	
	return 0;
}

/* shutdown socket descriptor routine */
int cnct_socket_shutdown(socket_t sd)
{
	LOG_IN;
	
	shutdown(sd, CNCT_SHUTDOWN_DUPLEX);
	cnct_socket_close(sd);
	
	LOG_OUT;
	
	return 0;
}

/* set connection on socket */
socket_t cnct_socket_connect(cnct_socket_t *sckt)
{
	LOG_IN;
	
	struct addrinfo *nodes, *node;
	int resolv;
	socket_t sd;
	
	/* init routine */
	MALLOC_TYPE(struct addrinfo, hints);
	
	hints->ai_family = AF_UNSPEC;
	hints->ai_socktype = sckt->type;
	
	if ((resolv = getaddrinfo(sckt->host, sckt->port, hints, &nodes)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(resolv));
		return -1;
	}
	
	for (node = nodes; node != NULL; node = node->ai_next) {
		if ((sd = socket(node->ai_family, node->ai_socktype, node->ai_protocol)) == -1) {
			perror("client: socket");
			continue;
		}
		
		if (sckt->type == SOCK_STREAM) {
			/* call on TCP, not needed for UDP */
			if (connect(sd, node->ai_addr, node->ai_addrlen) == -1) {
				cnct_socket_close(sd);
				perror("client: connect");
				continue;
			}
		}
		
		break;
	}
	
	if (node == NULL) {
		fprintf(stderr, "failed to connect\n");
		return -1;
	}
	
	if (sckt->node) {
		free(sckt->node);
		sckt->node = NULL;
	}
	
	MALLOC_PNTR_TYPE(struct addrinfo, sckt->node);
	memcpy(sckt->node, node, sizeof(struct addrinfo));
	
	DBG_ON(
		char addr[INET6_ADDRSTRLEN];
		cnct_socket_getstraddr(node, addr);
		DBG_INFO(printf("connecting to %s\n", addr));
	);
	
	freeaddrinfo(nodes);
	
	LOG_OUT;
	
	return sd;
}

/* send-whole-buffer routine */
int cnct_socket_send(cnct_socket_t *socket, char *msg, int len)
{
	LOG_IN;
	
	int r = 0;
	int tx = 0;
	
	while (tx < len) {
		CNCT_SEND(socket, msg, tx, len, r);
		if (r == -1) {
			break;
		}
		tx  += r;
		len -= r;
	}
	
	LOG_OUT;
	
	return r == -1 ? -1 : tx;
}

/* connect - send - close */
int cnct_socket_sendmsg(cnct_socket_t *socket, char *msg, int len)
{
	LOG_IN;
	
	if (!(socket->sd != -1 && socket->reuse)) {
		socket->sd = cnct_socket_connect(socket);
	}
	
	if (cnct_socket_send(socket, msg, len) == -1) {
		printf("error: can't send all\n");
	}
	
	DBG_INFO(printf("send to server:[%s]\n", msg));
	
	if (socket->autoclose) {
		cnct_socket_close(socket->sd);
	}
	
	LOG_OUT;
	
	return 0;
}

socket_t cnct_socket_listen(cnct_socket_t *sckt)
{
	LOG_IN;
	
	socket_t sd;
	
	struct addrinfo hints, *nodes, *node;
	int resolv;
	int on = 1;
	
	/* init routine */
	memset(&hints, 0, sizeof hints);
//	hints.ai_family = AF_UNSPEC;
	hints.ai_family = AF_INET6;
	hints.ai_socktype = sckt->type;
	hints.ai_flags = AI_PASSIVE;
//	hints.ai_protocol = IPPROTO_TCP;
	
	if ((resolv = getaddrinfo(NULL, sckt->port, &hints, &nodes)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(resolv));
		return 1;
	}
	
	/* loop through all the results and bind to the first we can */
	for (node = nodes; node != NULL; node = node->ai_next) {
		if ((sd = socket(node->ai_family, node->ai_socktype, node->ai_protocol)) == -1) {
			perror("server: socket");
			continue;
		}
		if (node->ai_family == AF_INET) {
			printf("bind AF_INET\n");
		} else if (node->ai_family == AF_INET6) {
			printf("bind AF_INET6\n");
		} else {
			printf("bind %d\n", node->ai_family);
		}

//	#ifdef CNCT_UNIXWARE
		if (sckt->type == SOCK_STREAM) {
			if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (char *) &on, sizeof(int)) == -1) {
				perror("setsockopt");
			}
		}
//	#endif /* CNCT_UNIXWARE */
		printf("server: port = %d\n", (((struct sockaddr_in *) node->ai_addr)->sin_port));
		if (bind(sd, node->ai_addr, node->ai_addrlen) == -1) {
			cnct_socket_close(sd);
			perror("server: bind");
			continue;
		}
		
		break;
	}
	
	if (node == NULL)  {
		fprintf(stderr, "server: failed to bind\n");
		return 2;
	}
	
	/* free structure since it's not using anymore */
	freeaddrinfo(nodes);
	
	if (sckt->type == SOCK_STREAM) {
		if (listen(sd, BACKLOG) == -1) {
			perror("listen");
			exit(1);
		}
	}
	
	printf("server: waiting for connections...\n");
	
	LOG_OUT;
	
	return sd;
}

socket_t cnct_socket_accept(socket_t ld)
{
	LOG_IN;
	
	socket_t ad;
	socklen_t slen;
	struct sockaddr_storage client;
	
	slen = sizeof(client);
	ad = accept(ld, (struct sockaddr *) &client, &slen);
	if (ad == -1) {
		perror("accept");
	}
	
	/* close parents' socket for accept() */
	cnct_socket_close(ld);
	
	LOG_OUT;
	
	return ad;
}

/* set socket for receive */
int cnct_socket_recv_(cnct_socket_t *socket, socket_t sd, char *msg)
{
	LOG_IN;
	
	int rx;
	
	if ((rx = recv(sd, msg, MAXDATASIZE-1, 0)) == -1) {
	    perror("recv");
	}
	
	printf("MSG: %s", msg);
	
	cnct_socket_close(sd);
	
	LOG_OUT;
	
	return rx;
}

/* recv-whole-buffer routine */
int cnct_socket_recv(cnct_socket_t *socket, socket_t sd, char *msg, int len)
{
	LOG_IN;
	
	int r = 0;
	int rx = 0;
	
	if (len == -1) {
		if ((r = recv(sd, msg, MAXDATASIZE-1, 0)) == -1) {
			perror("recv");
		} else {
			rx = r;
		}
	} else {
		while (rx < len) {
			
			//if (socket->type == SOCK_STREAM) {
				r = recv(sd, msg + rx, len, 0);
			//} else {
			//	r = recvfrom(socket->sd, msg + tx, len, socket->flags, socket->node->ai_addr, socket->node->ai_addrlen);
			//}
			
			if (r == -1) {
				break;
			}
			rx  += r;
			len -= r;
		}
	}
	
	LOG_OUT;
	
	return r == -1 ? -1 : rx;
}

/* listen - accept - recv - close */
int cnct_socket_recvmsg(cnct_socket_t *socket, char *msg)
{
	LOG_IN;
	
	int rx;
	socket_t ad, ld;
	
	ld = cnct_socket_listen(socket);
	ad = cnct_socket_accept(ld);
	rx = cnct_socket_recv(socket, ad, msg, -1);
	
	LOG_OUT;
	
	return rx;
}

#ifdef CNCT_WINSWARE

/* required routine for WinSock callback support */

struct thread_data {
	cnct_socket_t *socket;
	socket_t sd;
	struct sockaddr_storage client;
	int (*cb)(cnct_socket_t *, socket_t, sockaddr_storage);
};

DWORD WINAPI cnct_socket_request(void *data)
{
	
	(*((struct thread_data *) data)->cb) (
			(((struct thread_data *) data)->socket),
			(((struct thread_data *) data)->sd),
			(((struct thread_data *) data)->client)
	);
	
	if (((struct thread_data *) data)->socket->type == CNCT_TCP) {
		if (((struct thread_data *) data)->socket->autoclose) {
			cnct_socket_close((((struct thread_data *) data)->sd));
		}
	}
	
	return 0;
}

/* *** */

#endif

/* init server for processing accepted connections in callback */
int cnct_socket_server(cnct_socket_t *socket, int (*callback)(cnct_socket_t *, socket_t, struct sockaddr_storage))
{
	LOG_IN;
	
	socket_t ld, ad;
	socklen_t slen;
	struct sockaddr_storage client;
	
	slen = sizeof(client);
	
	ld = cnct_socket_listen(socket);
	
	while (1) {
		if (socket->type == SOCK_STREAM) {
			ad = accept(ld, (struct sockaddr *) &client, &slen);
			if (ad == -1) {
				perror("accept");
				continue;
			}
			
		#ifdef CNCT_UNIXWARE
			
			if (!fork()) {
				cnct_socket_close(ld);
	//			(*callback)(socket, ad);
				(*callback)(socket, ad, client);
				cnct_socket_close(ad);
				exit(0);
			}
			/* full disconnect from client */
			if (socket->autoclose) {
				cnct_socket_close(ad);
			}
			
		#else
			
			struct thread_data *tdata;
			tdata = (struct thread_data *) malloc(sizeof(struct thread_data)); /* TODO: free? */
			tdata->socket = socket;
			tdata->sd = ad;
			tdata->client = client;
			tdata->cb = callback;
			//tdata->cb = (int (*)(void *, socket_t)) callback;
			DWORD tid;
			CreateThread(NULL, NULL, cnct_socket_request, tdata, NULL, &tid);
			DBG_ON(printf("CREATE_THREAD\n"));
			
		#endif
		} else {
			
			DBG_ON(printf("recvfrom berfore\n"););
			//MALLOC_TYPE_SIZE(char, msg, MAXDATASIZE);
			char *msg = (char *) malloc(MAXDATASIZE);
			memset(msg, '\0', MAXDATASIZE);
			DBG_ON(printf("recvfrom -->\n"););
			ad = recvfrom(ld, msg, MAXDATASIZE-1, 0, (struct sockaddr *) &client, &slen);
			DBG_ON(printf("recvfrom <--\n"););
			if (ad == -1) {
				perror("recvfrom");
				continue;
			}
			DBG_ON(printf("recvfrom after\n"););
		#ifdef CNCT_UNIXWARE
			
			if (!fork()) {
				(*callback)(socket, ld, client);
				cnct_socket_close(ld);
				exit(0);
			}
			
		#else
			
			struct thread_data *tdata;
			tdata = (struct thread_data *) malloc(sizeof(struct thread_data)); /* TODO: free? */
			tdata->socket = socket;
			tdata->sd = ld;
			tdata->client = client;
			tdata->cb = callback;
			//tdata->cb = (int (*)(void *, socket_t)) callback;
			DWORD tid;
			CreateThread(NULL, NULL, cnct_socket_request, tdata, NULL, &tid);
			DBG_ON(printf("CREATE_THREAD\n"));
			
		#endif
			
		}
	}
	
	LOG_OUT;
	
	return 0;
}

