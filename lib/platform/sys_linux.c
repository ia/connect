
#include "../connect.h"

//#include <linux/if_ether.h>
//#include <linux/filter.h>

int cnct_filter_bpf(char *iface, socket_t sd)
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

socket_t cnct_packet_socket(int engine, int proto)
{
	LOG_IN;
	
	int rs;
	
	if (engine == CNCT_PACKENGINE_BPF) {
		rs = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	} else {
		(proto == IPPROTO_RAW) ? (rs = socket(CNCT_SOCKET_RAW)) : (rs = socket(CNCT_SOCKET_IP));
	}
	
	if (rs == CNCT_INVALID) {
		perror("socket");
		LOG_OUT_RET(-1);
	}
	
	LOG_OUT;
	
	return rs;
}

int cnct_packet_recv(socket_t rs, char *packet, int len)
{
	LOG_IN;
	LOG_OUT_RET(recvfrom(rs, packet, len, 0, NULL, NULL));
	//int rx = 0;
	
	//MALLOC_TYPE_SIZE(char, packet, cnct_mtu);
	
	//while (1) {
	//	memset(packet, '\0', cnct_mtu);
	//int rx = recvfrom(rs, packet, cnct_mtu, 0, NULL, NULL);
	//	cnct_packet_print(packet, proto, rx);
		//break;
	//}
}

socket_t cnct_packet_recv_init(int engine, char *iface, int proto, char *rule)
{
	LOG_IN;
	
	socket_t rs;
	
	if (rule) {
		engine = CNCT_PACKENGINE_PCP;
	}
	
	if (!engine) {
		engine = CNCT_PACKENGINE_BPF;
	}
	
	if (!proto) {
		proto = IPPROTO_RAW;
	}
	
	if (engine == CNCT_PACKENGINE_PCP) {
		cnct_filter_pcp(rule);
	} else if ((engine == CNCT_PACKENGINE_USR) || (engine == CNCT_PACKENGINE_BPF)) {
		/* TODO: implement call for `cnct_filter_bpf' when engine is BPF */
		if ((rs = cnct_packet_socket(engine, proto)) == CNCT_INVALID) {
			printf("error: can't set socket for dump\n");
			LOG_OUT_RET(1);
		}
	} else {
		printf("engine not supported\n");
		LOG_OUT_RET(1);
	}
	
	// cnct_packet_recv(proto, rs);
	
	LOG_OUT;
	
	return rs;
}

