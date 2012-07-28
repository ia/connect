
#include "../lib/connect.h" /* and nothing else,
			     * unless you'll see
			     * `implicit declaration' warning
			     */

#include <stdlib.h>
#ifdef CRAPWAY
#include <malloc.h>
#endif /* CRAPWAY */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

#define FDS 2

/*

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

int my_server(socket_t sd)
{
	printf("server socket: %d\n", sd);
	return 0;
}


/* stand alone connect API based sample for receiving one message over TCP socket */
int demo_recvmsg(const char *argv[])
{
	printf("receiving message:\n");
	printf("\tport: %s\n", argv[2]);
	
	char *msg = (char *) malloc(4 * 1024);
	memset(msg, '\0', 4 * 1024);
	cnct_socket_t *sckt_recv = cnct_socket_create(NULL, (char *) argv[2], CNCT_TCP, 0, 1, 0);
	cnct_socket_recvmsg_(sckt_recv, msg);
	cnct_socket_delete(sckt_recv);
	
	printf("\tmsg: %s\n", msg);
	
	return 0;
}

/* stand alone connect API based sample for sending one message over TCP socket */
int demo_sendmsg(const char *argv[])
{
	printf("sending message:\n");
	printf("\tmsg: %s\n", argv[2]);
	printf("\thost: %s\n", argv[3]);
	printf("\tport: %s\n", argv[4]);
	
	cnct_socket_t *socket = cnct_socket_create((char *) argv[3], (char *) argv[4], CNCT_TCP, 0, 1, 0);
	cnct_socket_sendmsg(socket, (char *) argv[2], strlen(argv[2]));
	cnct_socket_delete(socket);
	
	return 0;
}

/* usage helper */
int usage(const char *name)
{
	printf("Usage: %s <sample>\n", name);
	printf("\t<sample> - type of demo:\n");
	printf("\t\tsendmsg text host port\n");
	printf("\t\trecvmsg port\n");
	return 0;
}

/* main entry point in this demo */
int main(int argc, const char *argv[])
{
	LOG_IN;
	
	/* in case of Winsock - WSAStartup routine required */
	cnct_init();
	
	DBG_INFO(printf("platform: %s\n", SOCKET_STYLE));
	
	if (argc < 2) {
		return usage(argv[0]);
	}
	
	if ((strcmp(argv[1], "sendmsg") == 0) && (argc == 5)) {
		demo_sendmsg(argv);
	} else if ((strcmp(argv[1], "recvmsg") == 0) && (argc == 3)) {
		demo_recvmsg(argv);
	} else {
		return usage(argv[0]);
	}
	
	/*
	
	char *msg = "hello\n\0";
	char *port = "1234";
	
	tcp_sendmsg("::1", port, msg, strlen(msg), 0);
	tcp_sendmsg("localhost", port, msg, strlen(msg), 0);
	
	if (argc > 1) {
		tcp_sendmsg(argv[1], port, msg, strlen(msg), 0);
	}
	*/
	
/*
	char *msgng = "Cool struct api!!1\n\0";
	cnct_socket_t *socket = cnct_socket_create("localhost", "54321", CNCT_TCP, 0, 1, 0);
	printf("sending to socket fd: %d\n", socket->sd);
	cnct_socket_sendmsg(socket, msgng, strlen(msgng));
	cnct_socket_delete(socket);
*/

	/*
	char *msgng2 = "Continue receiving in the same socket! Yayye!!!1\n\0";
	printf("sending to socket fd: %d\n", socket->sd);
	cnct_socket_sendmsg(socket, msgng2, strlen(msgng2));
	printf("sending to socket fd: %d\n", socket->sd);
	
	cnct_socket_delete(socket);
	
	char *msg_udp = "UDP socket demo\n\0";
	cnct_socket_t *sckt = cnct_socket_create("localhost", "1234", CNCT_UDP, 0, 1, 0);
	cnct_socket_sendmsg(socket, msg_udp, strlen(msg_udp));
	cnct_socket_delete(sckt);
	
	*/
	
/*
	char *msg_recv = (char *) malloc(4 * 1024);
	memset(msg_recv, '\0', 4 * 1024);
	cnct_socket_t *sckt_recv = cnct_socket_create(NULL, "54321", CNCT_TCP, 0, 1, 0);
	cnct_socket_recvmsg_(sckt_recv, msg_recv);
	cnct_socket_delete(sckt_recv);
*/
	
	/*
	cnct_socket_t *sckt_server = cnct_socket_create(NULL, "1234", CNCT_TCP, 0, 1, 0);
	cnct_socket_server(sckt_server, my_server);
	cnct_socket_delete(sckt_server);
	*/


	/* in case of Winsock - WSACleanup routine */
	cnct_finish();
	
	LOG_OUT;
	return 0;
}

