
#include "connect.h"

#define cnct_mtu 1500

int cnct_packet_print(char *packet, int len)
{
	int i;
	for (i = 0; i < len; i++) {
		printf("%02X", *((unsigned char *) packet + i));
		if (i == 14) {
			printf("\n");
			break;
		} else {
			printf(" ");
		}
	}
	return 0;
}

int cnct_packet_promisc()
{
	return 0;
}

socket_t cnct_packet_socket(int engine)
{
	int rs;
#ifdef CNCT_UNIXWARE
	if (engine == CNCT_PACKENGINE_BPF) {
		rs = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	} else
#endif
		rs = socket(CNCT_SOCKET_RAW);
	
	if (rs == CNCT_INVALID) {
		perror("socket");
		return -1;
	}
	
	return rs;
}

int cnct_packet_recv(socket_t rs)
{
	int rx = 0;
	
	MALLOC_TYPE_SIZE(char, packet, cnct_mtu);
	
	while (1) {
		memset(packet, '\0', cnct_mtu);
		rx = recvfrom(rs, packet, cnct_mtu, 0, NULL, NULL);
		cnct_packet_print(packet, rx);
		//break;
	}
	
	return 0;
}

int cnct_filter_bpf(socket_t sd)
{
#ifdef CNCT_UNIXWARE
	struct sock_filter bpf[] = {
		{ 0x6, 0, 0, 0x0000ffff }
	};
	struct sock_fprog fprog;
	
	fprog.len = 1;
	fprog.filter = bpf;
	
	if (setsockopt(sd, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog)) < 0) {
		perror("setsockopt");
		cnct_socket_close(sd);
		return -1;
	}
#endif
	return 0;
}

int cnct_filter_pcp()
{
	return 0;
}

int cnct_packet_dump(int type, char *rule)
{
	LOG_IN;
	
	socket_t rs;
	
	if (rule) {
		type = CNCT_PACKENGINE_PCP;
	}
	
	if ((cnct_ware == CNCT_WINSWARE_VALUE) && (type == CNCT_PACKENGINE_BPF)) {
		type = CNCT_PACKENGINE_USR;
	}
	
	if (type != CNCT_PACKENGINE_PCP) {
		rs = cnct_packet_socket(type);
	}
	
	if (type == CNCT_PACKENGINE_BPF) {
		cnct_filter_bpf(rs);
	} else if (type == CNCT_PACKENGINE_PCP) {
		cnct_filter_pcp(rule);
	} else {
		;
	}
	
	cnct_packet_recv(rs);
	
	LOG_OUT;
	
	return 0;
}

