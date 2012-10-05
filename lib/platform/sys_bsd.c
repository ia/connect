
#include "../connect.h"

//#include <err.h>


//#include <netinet/in.h>
//#include <net/if.h>


//#include <net/bpf.h>

//#include <net/ethernet.h>



int open_device()
{
	int fd = -1;
	char dev[32];
	int i = 0;
	
	/* Open the bpf device */
	for (i = 0; i < 255; i++) {
		(void) snprintf(dev, sizeof(dev), "/dev/bpf%u", i);
		(void) printf("Trying to open: %s\n", dev);
		
		fd = open(dev, O_RDWR);
		if (fd > -1) {
			return fd;
		}
		
		switch (errno) {
			case EBUSY:
				break;
			default:
				return -1;
		}
	}
	
	errno = ENOENT;
	return -1;
}

int check_datalink(int fd)
{
	u_int32_t dlt = 0;
	
	/* Ensure we are dumping the datalink we expect */
	if (ioctl(fd, BIOCGDLT, &dlt) < 0) {
		return -1;
	}
	
	(void) fprintf(stdout, "datalink type=%u\n", dlt);
	
	switch (dlt) {
		case DLT_EN10MB:
			return 0;
		default:
			(void) fprintf(stderr, "Unsupported datalink type:%u", dlt);
			errno = EINVAL;
			return -1;
	}
}

int set_options(int fd, char *iface)
{
	struct ifreq ifr;
	u_int32_t enable = 1;
	
	/* Associate the bpf device with an interface */
	(void) strlcpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name)-1);
	
	if (ioctl(fd, BIOCSETIF, &ifr) < 0) {
		return -1;
	}
	
	/* Set header complete mode */
	if (ioctl(fd, BIOCSHDRCMPLT, &enable) < 0) {
		return -1;
	}
	
	/* Monitor packets sent from our interface */
	if (ioctl(fd, BIOCSSEESENT, &enable) < 0) {
		return -1;
	}
	
	/* Return immediately when a packet received */
	if (ioctl(fd, BIOCIMMEDIATE, &enable) < 0) {
		return -1;
	}
	
	return 0;
}

int set_filter(int fd)
{
	struct bpf_program fcode = {0};
	
	/* dump ssh packets only */
	struct bpf_insn insns[] = {
		{ 0x6, 0, 0, 0x0000ffff },
	};
	
	/* Set the filter */
	fcode.bf_len = sizeof(insns) / sizeof(struct bpf_insn);
	fcode.bf_insns = &insns[0];
	
	if (ioctl(fd, BIOCSETF, &fcode) < 0) {
		return -1;
	}
	
	return 0;
}

int packet_recv(int fd)
{
	char *buf = NULL;
	char *p = NULL;
	size_t blen = 0;
	ssize_t n = 0;
	struct bpf_hdr *bh = NULL;
	struct ether_header *eh = NULL;
	
	if (ioctl(fd, BIOCGBLEN, &blen) < 0) {
		return;
	}
	
	printf("blen = %d\n", blen);
	
	if ((buf = malloc(blen)) == NULL) {
		return;
	}
	
	(void) printf("reading packets ...\n");
	
	for ( ; ; ) {
		(void) memset(buf, '\0', blen);
		
		n = read(fd, buf, blen);
		
		if (n <= 0) {
			return;
		}
		
		p = buf;
		while (p < buf + n) {
			bh = (struct bpf_hdr *)p;
			
			/* Start of ethernet frame */
			eh = (struct ether_header *)(p + bh->bh_hdrlen);
			
			(void) printf(
				"%02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x [type=%u]\n",
				
				eh->ether_shost[0], eh->ether_shost[1], eh->ether_shost[2],
				eh->ether_shost[3], eh->ether_shost[4], eh->ether_shost[5],
				
				eh->ether_dhost[0], eh->ether_dhost[1], eh->ether_dhost[2],
				eh->ether_dhost[3], eh->ether_dhost[4], eh->ether_dhost[5],
				
				eh->ether_type
				);
				
			p += BPF_WORDALIGN(bh->bh_hdrlen + bh->bh_caplen);
		}
	}
	
	return 0;
}

socket_t cnct_filter_bpf(char *iface, socket_t rs)
{
	int fd = 0;
	// char *iface = NULL;
	
	// iface = strdup(argc < 2 ? "en1" : iface);
	/*
	if (iface == NULL) {
		err(EXIT_FAILURE, "strdup");
	}
	*/
	
	fd = open_device();
	
	if (fd < 0) {
		err(EXIT_FAILURE, "open_device");
	}
	
	if (set_options(fd, (iface == NULL ? "en0" : iface)) < 0) {
		err(EXIT_FAILURE, "set_options");
	}
	
	if (check_datalink(fd) < 0) {
		err(EXIT_FAILURE, "check_datalink");
	}
	
	if (set_filter(fd) < 0) {
		err(EXIT_FAILURE, "set_filter");
	}
	
	/*
	size_t blen = 0;
	if (ioctl(fd, BIOCGBLEN, &blen) < 0) {
		perror("ioctl");
		return -1;
	}
	printf("blen = %d\n", blen);
	*/
	
	//packet_recv(fd);
	
	// err(EXIT_FAILURE, "packet_recv");
	
	return fd;
}

socket_t cnct_packet_socket(int engine, int proto)
{
	LOG_IN;
	
	int rs;
	
	proto == IPPROTO_RAW ? (rs = socket(CNCT_SOCKET_RAW)) : (rs = socket(CNCT_SOCKET_IP));
	
	if (rs == CNCT_INVALID) {
		perror("socket");
		LOG_OUT_RET(-1);
	}
	
	LOG_OUT;
	
	return rs;
}

int cnct_packet_recv(socket_t fd, char *packet, int len)
{
	char *mbuf = NULL;
	char *p = NULL;
	//size_t blen = 0;
	ssize_t n = 0;
	struct bpf_hdr *bh = NULL;
	struct ether_header *eh = NULL;
	
	/*
	if (ioctl(fd, BIOCGBLEN, &blen) < 0) {
		return;
	}
	
	printf("blen = %d\n", blen);
	*/
	if ((mbuf = malloc(len)) == NULL) {
		return;
	}
	
	
	(void) printf("reading packet ...\n");
	
	
	(void) memset(mbuf, '\0', len);
		
	n = read(fd, mbuf, len);
	
	if (n <= 0) {
		return n;
	}
	
	p = mbuf;
	while (p < mbuf + n) {
		bh = (struct bpf_hdr *)p;
		
		/* Start of ethernet frame */
		eh = (struct ether_header *)(p + bh->bh_hdrlen);
	//	memcpy(packet, p + bh->bh_hdrlen, bh->bh_hdrlen);
		//packet = (p + bh->bh_hdrlen);
		(void) printf(
			"%02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x [type=%u] [n=%d] [l=%d] [h=%d]\n",
			
			eh->ether_shost[0], eh->ether_shost[1], eh->ether_shost[2],
			eh->ether_shost[3], eh->ether_shost[4], eh->ether_shost[5],
			
			eh->ether_dhost[0], eh->ether_dhost[1], eh->ether_dhost[2],
			eh->ether_dhost[3], eh->ether_dhost[4], eh->ether_dhost[5],
			
			eh->ether_type,
			n,
			bh->bh_caplen,
			bh->bh_hdrlen
			);
		memcpy(packet, p + bh->bh_hdrlen, bh->bh_caplen);
		p += BPF_WORDALIGN(bh->bh_hdrlen + bh->bh_caplen);
	}
	
	return bh->bh_caplen;
}

socket_t cnct_packet_recv_init(int engine, char *iface, int proto, char *rule)
{
	LOG_IN;
	
	socket_t rs = CNCT_ERROR;
	
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
	} else if (engine == CNCT_PACKENGINE_USR) {
		if ((rs = cnct_packet_socket(engine, proto)) == CNCT_INVALID) {
			printf("error: can't set socket for dump\n");
			LOG_OUT_RET(1);
		}
	} else if (engine == CNCT_PACKENGINE_BPF) {
		rs = cnct_filter_bpf(iface, 0);
	} else {
		printf("engine not supported\n");
		LOG_OUT_RET(1);
	}
	
	LOG_OUT;
	
	return rs;
}

