

/*

packet_open
packet_recv
packet_send
packet_close

packet_dump
packet_loop(n, callback)

*/


#include "connect.h"


socket_t cnct_packet_open(int engine, char *iface, int proto, char *rule)
{
	return sys_packet_open(engine, iface, proto, rule);
}


ssize_t cnct_packet_recv(socket_t rs, unsigned char *packet, size_t len)
{
	return sys_packet_recv(rs, packet, len);
}


ssize_t cnct_packet_send(socket_t ss, unsigned char *packet, size_t len, char *iface)
{
	return sys_packet_send(ss, packet, len, iface);
}


socket_t cnct_packet_close(socket_t cs)
{
	return sys_packet_close(cs);
}


int cnct_packet_stats(socket_t ss)
{
	return sys_packet_stats(ss);
}


int cnct_packet_dump(int engine, char *iface, int proto, char *rule, int (*callback)(unsigned char *, int, ssize_t))
{
	LOG_IN;
	
	if (!callback) {
		callback = &cnct_packet_print;
	}
	
	socket_t rs = cnct_packet_open(engine, iface, proto, rule);
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
	
	LOG_OUT;
	
	return 0;
}


/* TODO:
 * - pass `N' packets
 * - pass socket - do packet_open only if socket is invalid
 */
int cnct_packet_loop(int engine, char *iface, int proto, char *rule, int (*callback)(unsigned char *, int, ssize_t))
{
	LOG_IN;
	int r = 0;
	r = sys_signal();
	if (r) {
		return r;
	}
	
	if (!callback) {
		callback = &cnct_packet_print;
	}
	
	socket_t rs = cnct_packet_open(engine, iface, proto, rule);
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
	int tp_recv = 0;
	cnct_packet_stats(rs); /* reset stats */
	while (!g_cnct_kill) {
		(void) memset(packet, '\0', len);
		DBG_INFO(printf("\nRX --->\n");)
		rx = cnct_packet_recv(rs, packet, len);
		DBG_INFO(printf("\nRX <---\n");)
		if (rx == -1) {
			perror("loop: recv");
			printf("(%d)\n", errno);
		} else if (rx == 0) {
			printf("loop: client shutdown\n");
		} else {
			DBG_INFO(printf("\ncallback --->\n");)
			(*callback)(packet, proto, rx);
			tp_recv++;
			DBG_INFO(printf("\ncallback <---\n");)
		}
	}
	
	printf("tp_recv = %d\n", tp_recv);
	cnct_packet_stats(rs);
	cnct_packet_close(rs);
	
	LOG_OUT;
	
	return 0;
}


int cnct_packet_print(unsigned char *packet, int proto, ssize_t len)
{
	LOG_IN;
	UNUSED(proto);
	
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
	
	LOG_OUT;
	return 0;
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


