
#include "../lib/connect.h"
/* and nothing else, unless you'll see `implicit declaration' warning */

/*

#define FDS 2

int recv_data(int s)
{
	int size = 4096;
	char msg[size];
	memset(msg, '\0', size);
	int r = tcp_recv(s, msg, size, 0);
	if (r > 0) {
		printf("%s", msg);
	}
	return r;
}

int send_data(int s)
{
	char *line = NULL;
	size_t len = 0;
	ssize_t sz;
	FILE *fp;
	fp = fopen("/dev/stdin", "r");
	sz = getline(&line, &len, fp);
	tcp_send(s, line, sz, 0);
	return 0;
}

int nc_client_tcp(int argc, const char *argv[])
{
	int s = tcp_connect("localhost", "1234");
	if (s < FDS) {
		printf("error: tcp_connect\n");
	} else {
		printf("socket_fd = %d\n", s);
		//make_socket_non_blocking(s);
		
		if (!fork()) {
			while (recv_data(s) > 0) {
				;
			}
		}
		while (1) {
			send_data(s);
		}
	}
	
	return 0;
}

*/

/* stand alone connect API based sample for socket UDP server */

/* server callback */
int your_udp_server(cnct_socket_t *socket, socket_t sd, struct sockaddr_storage client, cnct_sockdata_t udp_data)
{
	printf("server socket: %d\n", sd);
	
	printf("recv msg[%d]: %s\n", udp_data.len, udp_data.data);
	
	char *msg = "echo server\n\0";
	int len = strlen(msg);
	socklen_t slen = sizeof(client);
	sendto(sd, msg, len, 0, (struct sockaddr *) &client, slen);
	
	printf("---> place your code here for send/recv <----\n");
	//cnct_socket_close(sd);
	printf("---> exit. Waiting for new connection now ... <----\n");
	
	return 0;
}

/* server init */
int demo_udp_server(const char *argv[])
{
	printf("starting server:\n");
	printf("\tport: %s\n", argv[2]);
	
	cnct_socket_t *sckt_server = cnct_socket_create(NULL, (char *) argv[2], AF_INET, SOCK_DGRAM, 0, 0, 0);
	cnct_socket_server(sckt_server, your_udp_server);
	cnct_socket_delete(sckt_server);
	
	return 0;
}

/* stand alone connect API based sample for socket TCP server */

/* server callback */
int your_tcp_server(cnct_socket_t *socket, socket_t sd, struct sockaddr_storage client, cnct_sockdata_t udp_data)
{
	if (udp_data.len != -1) {
		printf("something goes wrong\n");
	}
	
	printf("server socket: %d\n", sd);
	char *msg = "echo server\n\0";
	int len = strlen(msg);
	send(sd, msg, len, 0);
	printf("---> place your code here for send/recv <----\n");
	if (socket->autoclose != 1) {
		printf("---- Don't forget to close socket manually after you're done ----\n");
		cnct_socket_shutdown(sd); /* TODO : FIXME */
		//cnct_socket_close(sd);
	}
	printf("---> exit. Waiting for new connection now ... <----\n");
	return 0;
}

/* server init */
int demo_tcp_server(const char *argv[])
{
	printf("starting server:\n");
	printf("\tport: %s\n", argv[2]);
	
	cnct_socket_t *sckt_server = cnct_socket_create(NULL, (char *) argv[2], AF_INET, SOCK_STREAM, 0, 0, 0);
	cnct_socket_server(sckt_server, your_tcp_server);
	cnct_socket_delete(sckt_server);
	
	return 0;
}

/* *** *** *** *** *** *** *** *** *** */

/* stand alone connect API based sample for receiving one message over TCP socket */
int demo_tcprecvmsg(const char *argv[])
{
	printf("receiving message:\n");
	printf("\tport: %s\n", argv[2]);
	
	char *msg = (char *) malloc(4 * 1024);
	memset(msg, '\0', 4 * 1024);
	cnct_socket_t *sckt_recv = cnct_socket_create(NULL, (char *) argv[2], AF_INET, SOCK_STREAM, 0, 1, 0);
	cnct_socket_recvmsg(sckt_recv, msg, 0);
	cnct_socket_delete(sckt_recv);
	
	printf("\tmsg: %s\n", msg);
	
	return 0;
}

/* stand alone connect API based sample for receiving one message over TCP socket */
int demo_udprecvmsg(const char *argv[])
{
	printf("receiving message:\n");
	printf("\tport: %s\n", argv[2]);
	
	MALLOC_SOCKDATA(msg, 4096);
	msg->len = 8;
	
	cnct_socket_t *sckt_recv = cnct_socket_create(NULL, (char *) argv[2], AF_INET, SOCK_DGRAM, 0, 1, 0);
	cnct_socket_recvmsg(sckt_recv, msg->data, msg->len);
	cnct_socket_delete(sckt_recv);
	
	printf("\twhole udp msg: %s\n", msg->data);
	printf("\tlen'd udp msg: ");
	cnct_sockdata_print(msg->data, msg->size, msg->len);
	printf("\n");
	
	return 0;
}

/* stand alone connect API based sample for sending one message over TCP socket */
int demo_tcpsendmsg(const char *argv[])
{
	printf("sending message:\n");
	printf("\tmsg: %s\n", argv[2]);
	printf("\thost: %s\n", argv[3]);
	printf("\tport: %s\n", argv[4]);
	
	cnct_socket_t *socket = cnct_socket_create((char *) argv[3], (char *) argv[4], AF_INET, SOCK_STREAM, 0, 1, 0);
	cnct_socket_sendmsg(socket, (char *) argv[2], strlen(argv[2]));
	cnct_socket_delete(socket);
	
	return 0;
}

/* usage helper */
int usage(const char *name)
{
	printf("Usage: %s <sample>\n", name);
	printf("\t<sample> - type of demo:\n");
	printf("\t\ttcpsendmsg text host port\n");
	printf("\t\ttcprecvmsg port\n");
	printf("\t\ttcpserver  port\n");
	printf("\t\tudprecvmsg port\n");
	printf("\t\tudpserver  port\n");
	return 0;
}

/* main entry point in this demo */
int main(int argc, const char *argv[])
{
	LOG_IN;
	
	/* in case of Winsock - WSAStartup routine required */
	cnct_start();
	
	DBG_INFO(printf("platform: %s\n", CNCT_SOCKETS));
	
	if (argc < 2) {
		return usage(argv[0]);
	}
	
	if ((strcmp(argv[1], "tcpsendmsg") == 0) && (argc == 5)) {
		demo_tcpsendmsg(argv);
	} else if ((strcmp(argv[1], "tcprecvmsg") == 0) && (argc == 3)) {
		demo_tcprecvmsg(argv);
	} else if ((strcmp(argv[1], "tcpserver") == 0) && (argc == 3)) {
		demo_tcp_server(argv);
	} else if ((strcmp(argv[1], "udprecvmsg") == 0) && (argc == 3)) {
		demo_udprecvmsg(argv);
	} else if ((strcmp(argv[1], "udpserver") == 0) && (argc == 3)) {
		demo_udp_server(argv);
	} else {
		return usage(argv[0]);
	}
	
	/* in case of Winsock - WSACleanup routine */
	cnct_finish();
	
	LOG_OUT;
	return 0;
}

