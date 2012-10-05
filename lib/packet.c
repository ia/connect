
#include "connect.h"

//#define cnct_mtu 64*1024

int cnct_packet_print(char *packet, int proto, int len)
{
	/* TODO: FIXME: if proto == IPPROTO_IP && cnct_sys == LINUX { seek packet to IP header before process } */
	int i;
	printf("[len=%d] ", len);
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

#ifdef FALSE
socket_t cnct_packet_socket(int engine, int proto)
{
	LOG_IN;
	
	int rs;
#ifdef CNCT_SYS_LINUX
	if (engine == CNCT_PACKENGINE_BPF) {
		rs = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	} else
#endif
		(proto == IPPROTO_RAW) ? (rs = socket(CNCT_SOCKET_RAW)) : (rs = socket(CNCT_SOCKET_IP));
	
	if (rs == CNCT_INVALID) {
		perror("socket");
		LOG_OUT_RET(-1);
	}
	
	LOG_OUT;
	
	return rs;
}
#endif

#ifdef FALSE
int cnct_packet_recv(socket_t rs, int proto)
{
	LOG_IN;
	
	int rx = 0;
	
	MALLOC_TYPE_SIZE(char, packet, cnct_mtu);
	
	while (1) {
		memset(packet, '\0', cnct_mtu);
		rx = recvfrom(rs, packet, cnct_mtu, 0, NULL, NULL);
		cnct_packet_print(packet, proto, rx);
		//break;
	}
	
	LOG_OUT;
	
	return 0;
}
#endif

/*
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
*/
int cnct_filter_pcp(char *rule)
{
	return 0;
}

int cnct_packet_dump(int engine, char *iface, int proto, char *rule, int (*callback)(char *, int, int))
{
	LOG_IN;
	
	if (!callback) {
		callback = &cnct_packet_print;
	}
	
	socket_t rs = cnct_packet_recv_init(engine, iface, proto, rule);
	
	int rx = 1;
	
	MALLOC_TYPE_SIZE(char, packet, cnct_mtu);
	
	//while (rx > 0) {
		memset(packet, '\0', cnct_mtu);
		rx = cnct_packet_recv(rs, packet, cnct_mtu);
		if (rx == -1) {
			perror("dump: recv");
		} else if (rx == 0) {
			printf("dump: client shutdown\n");
		} else {
			(*callback)(packet, proto, rx);
		}
	//}
	
	LOG_OUT;
	
	return 0;
}

#ifdef FALSE
int cnct_packet_dump(int engine, char *iface, int proto, char *rule, int (*callback)(char *, int, int))
{
	LOG_IN;
	
	if (!callback) {
		callback = &cnct_packet_print;
	}
	/*
	 * doing the following things here:
	 * - rule exists? using PCAP
	 * - no rule?
	 *  -- using TYPE, but:
	 *  --- BPF on NT? NO. _USR only
	 *  --- USR on BSD/OSX? NO. _BPF only
	 */
	
	/*
		linux   : usr  bpf  pcp
		bsd/osx : usr* bpf  pcp
		win     : usr  usr* pcp
		_____
		* not all packets
	*/
	
	/* TODO: develop default policies (if type/iface/proto/rule/... not provided) */
	
	/* receive socket */
	socket_t rs;
	
	/* dump socket */
	socket_t ds;
	
	if (rule) {
		engine = CNCT_PACKENGINE_PCP;
	}
	
	if (!engine) {
		/* trying to set up default type if not provided */
		cnct_sys == CNCT_SYS_NT_T ? (engine = CNCT_PACKENGINE_USR) : (engine = CNCT_PACKENGINE_BPF);
	}
	
	if (!proto) {
		cnct_sys == CNCT_SYS_LINUX_T ? (proto = IPPROTO_RAW) : (proto = IPPROTO_IP);
	}
	
	if ((cnct_api == CNCT_API_NT_TYPE) && (engine == CNCT_PACKENGINE_BPF)) {
		engine = CNCT_PACKENGINE_USR;
	}
	
	//if (((cnct_sys == CNCT_SYS_BSD_T) || (cnct_sys == CNCT_SYS_OSX_T)) && (type == CNCT_PACKENGINE_USR)) {
	//if (((cnct_sys == CNCT_SYS_OSX_T)) && (type == CNCT_PACKENGINE_USR)) {
	/*
	if (type == CNCT_PACKENGINE_USR) {
		type = CNCT_PACKENGINE_BPF;
	}
	*/
	
	DBG_ON(printf("engine : %d [ USR=%d BPF=%d PCP=%d ]\n", engine, CNCT_PACKENGINE_USR, CNCT_PACKENGINE_BPF, CNCT_PACKENGINE_PCP);)
	DBG_ON(printf("proto  : %d [ RAW=%d IP=%d ]\n", proto, IPPROTO_RAW, IPPROTO_IP);)
	
	if (engine != CNCT_PACKENGINE_PCP) {
		if ((rs = cnct_packet_socket(engine, proto)) == CNCT_INVALID) {
			printf("error: can't set socket for dump\n");
			return 1;
		}
	}
	
	if (engine == CNCT_PACKENGINE_BPF) {
		if (cnct_filter_bpf(iface, rs) == CNCT_ERROR) {
			printf("error: can't set BPF filter\n");
			return CNCT_ERROR;
		}
	} else if (engine == CNCT_PACKENGINE_PCP) {
		cnct_filter_pcp(rule);
	} else if (engine == CNCT_PACKENGINE_USR) {
	#ifdef CNCT_SYS_NT
		//if (proto == IP) {
			cnct_filter_bpf(); /* proto */
		//}
	#else
		cnct_packet_recv(proto, rs);
	#endif /* CNCT_SYS_NT */
		;
	} else {
		printf("engine not supported\n");
		return 1;
	}
	
	//cnct_packet_recv(rs);
	
	LOG_OUT;
	
	return 0;
}
#endif

