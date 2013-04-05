

#include "../connect.h"


int sys_filter_bpf(socket_t sd)
{
	struct sock_filter bpf[] = { CNCT_BPF_PCKT };
	struct sock_fprog fprog;
	
	fprog.len = 1;
	fprog.filter = bpf;
	
	if (setsockopt(sd, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog)) < 0) {
		perror("setsockopt");
		cnct_socket_close(sd);
		return CNCT_ERROR;
	}
	
	return 0;
}


int sys_filter_bind(char *iface)
{
	LOG_IN;
	if (iface) {
	/* TOOD: implement
	bind(...)
	*/
	}
	LOG_OUT;
	return 0;
}


socket_t cnct_packet_open(int engine, char *iface, int proto, char *rule)
{
	LOG_IN;
	socket_t ps;
	
	if (rule) {
		engine = CNCT_PACKENGINE_PCP;
	}
	
	if (!engine) {
		engine = CNCT_PACKENGINE_BPF;
	}
	
	if (!proto) {
		proto = IPPROTO_RAW;
	}
	
	/* TODO: implement IS_SOCKET_VALID define */
	switch (engine) {
		case CNCT_PACKENGINE_PCP:
			/* cnct_filter_pcp(rule); */
			printf("error: not implemented\n");
			LOG_OUT_RET(1);
			break;
		case CNCT_PACKENGINE_BPF:
			ps = socket(CNCT_SOCKET_RAW);
			if (ps == CNCT_INVALID) {
				printf("error: can't set socket for dump\n");
				LOG_OUT_RET(1);
			}
			if (iface) { sys_filter_bind(iface) ? ps = -1 : 0 ; }
			if (sys_filter_bpf(ps)) {
				printf("error: can't set socket for dump\n");
				LOG_OUT_RET(1);
			}
			break;
		case CNCT_PACKENGINE_USR:
			(proto == IPPROTO_RAW) ? (ps = socket(CNCT_SOCKET_RAW)) : (ps = socket(CNCT_SOCKET_IP));
			if (ps == CNCT_INVALID) {
				printf("error: can't set socket for dump\n");
				LOG_OUT_RET(1);
			}
			if (iface) { sys_filter_bind(iface); }
			break;
		default:
			printf("engine not supported\n");
			LOG_OUT_RET(1);
			break;
	}
	
	LOG_OUT;
	return ps;
}


ssize_t cnct_packet_recv(socket_t rs, unsigned char *packet, size_t len)
{
	LOG_IN;
	LOG_OUT_RET(recvfrom(rs, packet, len, 0, NULL, NULL));
}


ssize_t cnct_packet_send(socket_t ss, unsigned char *packet, size_t len)
{
	LOG_IN;
	LOG_OUT_RET(sendto(ss, packet, len, 0, NULL, 0));
}


int cnct_packet_close(socket_t cs)
{
	LOG_IN;
	LOG_OUT_RET(close(cs));
}


