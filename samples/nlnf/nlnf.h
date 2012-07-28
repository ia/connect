
struct nlnf {
	unsigned char hw_addr_dest[6];
	unsigned int filter;
	struct ethhdr *eth_hdr;
	unsigned char hw_addr_src[6];
	// struct  iphdr *  ip_hdr;
} __attribute__((packed));

struct nlnf_pf {
	unsigned char hw_addr_src[6];
	unsigned char hw_addr_dest[6];
	unsigned int filter;
	struct ethhdr *eth_hdr;
	// struct  iphdr *  ip_hdr;
} __attribute__((packed));

struct nlnf_pkt_legacy {
	unsigned char *mac_hdr;
	unsigned char *net_hdr;
	unsigned char *trp_hdr;
} __attribute__((packed));

struct nlnf_pkt {
	__u16 mac_len;
	unsigned char *mac_hdr;
	unsigned char *net_hdr;
	unsigned char *trp_hdr;
} __attribute__((packed));

/*
struct nlnf {
	unsigned char hw_addr_dest[6];
	unsigned int filter;
} __attribute__((packed));
*/

