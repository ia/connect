
#include "connect.h"

#define cnct_mtu 1500

/*
dump(callback)

setup card
open socket
recv packet
	callback(packet)
*/

int cnct_packet_print(char *packet, int len)
{
	int i;
	for (i = 0; i < len; i++) {
		if (i != 0) {
			if (i < 12) {
				if (i % 6 == 0) {
					printf(" ");
				} else {
					printf(":");
				}
			} else {
				printf(" ");
			}
		} /*
			printf("\n i == %d\n", i % 6);
			if ((i % 6) == 0) {
			} else {
				printf(":");
			}
		}*/
		printf("%02X", *((unsigned char *) packet + i));
		if (i == 14) {
			printf("\n");
			break;
		}
	}
	return 0;
}

int cnct_packet_promisc()
{
	return 0;
}

int cnct_packet_socket()
{
	int rs;
	if ((rs = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) == -1) {
	//if ((rs = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
		perror("socket");
		return -1;
	}
	
	return rs;
}

int cnct_packet_recv()
{
	int rx = 0;
	int rs;
	
	if ((rs = cnct_packet_socket()) == -1) {
		return -1;
	}
	
	MALLOC_TYPE_SIZE(char, packet, cnct_mtu);
	/*
	char *packet = (char *) malloc(cnct_mtu);
	if (!packet) {
		printf("malloc error\n");
		return -1;
	}
	*/
	
	while (1) {
		memset(packet, '\0', cnct_mtu);
		rx = recvfrom(rs, packet, cnct_mtu, 0, NULL, NULL);
		cnct_packet_print(packet, rx);
		break;
	}
	
	return 0;
}

int cnct_packet_dump(int type)
{
	switch (type) {
		case CNCT_PACKENGINE_USR:
			printf("built-in userspace\n");
			break;
		case CNCT_PACKENGINE_BPF:
			if (cnct_ware == CNCT_WINSWARE_VALUE) {
				printf("built-in userspace\n");
			} else {
				printf("built-in bpf rule\n");
			}
			break;
		case CNCT_PACKENGINE_PCP:
			printf("external bpf pcap\n");
			break;
		default:
			printf("built-in userspace\n");
			break;
	}
	
	return 0;
}

