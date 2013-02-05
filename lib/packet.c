
#include "connect.h"

//#define cnct_mtu 64*1024

int cnct_packet_print_legacy(unsigned char *packet, int proto, ssize_t len)
{
	LOG_IN;
	
	/* TODO: FIXME: if proto == IPPROTO_IP && cnct_sys == LINUX { seek packet to IP header before process } */
	ssize_t i;
	printf("[len=%zd] ", len);
	for (i = 0; i < len; i++) {
		printf("%02X", *((unsigned char *) packet + i));
		if (i == 14) {
			printf("\n");
			break;
		} else {
			printf(" ");
		}
	}
	
	LOG_OUT;
	return 0;
}

int cnct_packet_print(unsigned char *packet, int proto, ssize_t len)
{
	
	LOG_IN;
	
	ssize_t i;
	
	if (len > 14) {
		// dump ethernet header:
		// 00:11:22:33:44:55 <<< 55:44:33:22:11:00 | 0x0000 | ...
		size_t len_eth = 50;
		char *str_eth = (char *) malloc(len_eth);
		if (!str_eth) {
			printf("malloc error\n");
			return ENOMEM;
		}
		
		snprintf(str_eth, len_eth, "%02X:%02X:%02X:%02X:%02X:%02X <<< %02X:%02X:%02X:%02X:%02X:%02X | 0x%02X%02X |",
			packet[0], packet[1], packet[2], packet[3], packet[4], packet[5],
				packet[6], packet[7], packet[8], packet[9], packet[10], packet[11],
					packet[12], packet[13]);
		
		printf("[len=%05zd] ", len);
		printf("%s", (char *) str_eth);
		
		struct ether_header *eth = NULL;
		eth = (struct ether_header *) packet;
		if (eth->ether_type == 0x0008) {
			printf("[IP]");
			
			struct ip *iph = NULL;
			iph = (struct ip *) (packet + (2 * ETHER_ADDR_LEN) + 2);
			printf(" | ver=%u",      iph->ip_v);
			
			/* TODO: implementing print.c for packet output management to avoid such crap */
			if (iph->ip_v == 4) {
				char *ip_src = (char *) malloc(INET_ADDRSTRLEN);
				char *ip_dst = (char *) malloc(INET_ADDRSTRLEN);
				
				inet_ntop(AF_INET, &iph->ip_src, ip_src, INET_ADDRSTRLEN);
				inet_ntop(AF_INET, &iph->ip_dst, ip_dst, INET_ADDRSTRLEN);
				
				printf(" | %s >>> %s",    ip_src, ip_dst);
				printf(" | proto=0x%02X", iph->ip_p);
				printf(" | cksm=0x%04X",  iph->ip_sum);
				
				free(ip_dst);
				free(ip_src);
			}
		}
		
		printf("\n");
		free(str_eth);
	}
	
	/*
	printf("[len=%zd] ", len);
	for (i = 0; i < len; i++) {
		printf("%02X",  packet[i]);
		if (i == 14) {
			printf("\n");
			break;
		} else {
			printf(" ");
		}
	}
	*/
	
	LOG_OUT;
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
	
	MALLOC_TYPE_SIZE(unsigned char, packet, cnct_mtu);
	
	while (1) {
		memset(packet, '\0', cnct_mtu);
		rx = recvfrom(rs, (char *) packet, cnct_mtu, 0, NULL, NULL);
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

int cnct_packet_dump(int engine, char *iface, int proto, char *rule, int (*callback)(unsigned char *, int, ssize_t))
{
	LOG_IN;
	
	if (!callback) {
		callback = &cnct_packet_print;
	}
	
	socket_t rs = cnct_packet_recv_init(engine, iface, proto, rule);
	/* TODO: cnct_packet_len */
	
	ssize_t rx = 0;
	
	/* TODO: fix this crap; implement cnct_iface_getlen */
	size_t len = 0;
#ifdef CNCT_SYS_BSD
	if (ioctl(rs, BIOCGBLEN, &len) < 0) {
		perror("ioctl");
		return errno;
	}
#else
	len = cnct_mtu;
#endif
	
	DBG_INFO(printf("\nLEN == %zd\n", len);)
	MALLOC_TYPE_SIZE(unsigned char, packet, len);
	
	//while (rx > 0) {
		(void) memset(packet, '\0', len);
		DBG_INFO(printf("\nRX --->\n");)
		rx = cnct_packet_recv(rs, packet, len);
		DBG_INFO(printf("\nRX <---\n");)
		if (rx == -1) {
			perror("dump: recv");
		} else if (rx == 0) {
			printf("dump: client shutdown\n");
		} else {
			DBG_INFO(printf("\ncallback --->\n");)
			(*callback)(packet, proto, rx);
			DBG_INFO(printf("\ncallback <---\n");)
		}
	//}
	
	LOG_OUT;
	
	return 0;
}

#if 0
int cnct_packet_dump(int engine, char *iface, int proto, char *rule, int (*callback)(unsigned char *, int, ssize_t))
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

