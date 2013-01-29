
#include "../connect.h"

int set_device()
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

int get_datalink(int fd)
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
	struct bpf_program fcode = { 0 };
	struct bpf_insn insns[] = { CNCT_BPF_PCKT };
	
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
		return errno;
	}
	
	printf("blen = %d\n", blen);
	
	if ((buf = malloc(blen)) == NULL) {
		return ENOMEM;
	}
	
	(void) printf("reading packets ...\n");
	
	for ( ; ; ) {
		(void) memset(buf, '\0', blen);
		
		n = read(fd, buf, blen);
		
		if (n <= 0) {
			return n;
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
	LOG_IN;
	
	int fd = 0;
	
	if ((fd = set_device()) < 0) {
		err(EXIT_FAILURE, "set_device");
	}
	
	if (set_options(fd, ((iface == NULL) ? "en0" : iface)) < 0) {
		err(EXIT_FAILURE, "set_options");
	}
	
	if (get_datalink(fd) < 0) {
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
	
	LOG_OUT_RET(fd);
	//return fd;
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

/*
 * http://www.opensource.apple.com/source/xnu/xnu-792.13.8/bsd/net/bpf.h
 *  Structure prepended to each packet.

struct bpf_hdr {
	struct timeval  bh_tstamp;   // time stamp
	bpf_u_int32     bh_caplen;   // length of captured portion
	bpf_u_int32     bh_datalen;  // original length of packet
	u_short         bh_hdrlen;   // length of bpf header (this struct plus alignment padding)
};
*/

ssize_t cnct_packet_recv(socket_t fd, unsigned char *packet, size_t len)
{
	LOG_IN;
	
	char *mbuf = NULL;
	char *pbuf = NULL;
	ssize_t rx = 0;
	struct bpf_hdr *bh = NULL;
	struct ether_header *eh = NULL;
	
	// TODO: fix len management: rx_len / rq_len
	if (ioctl(fd, BIOCGBLEN, &len) < 0) {
		return errno;
	}
	
	if ((mbuf = malloc(len)) == NULL) {
		return errno;
	}
	
	(void) memset(mbuf, '\0', len);
	
	if ((rx = read(fd, mbuf, len)) <= 0) {
		return rx;
	}
	
	pbuf = mbuf;
	while (pbuf < mbuf + rx) {
		bh = (struct bpf_hdr *) pbuf;
		
		/* Start of ethernet frame */
		eh = (struct ether_header *)(pbuf + bh->bh_hdrlen);
		
		(void) printf(
			"%02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x [type=%u] [rx=%d] [caplen=%d] [datalen=%d] [hdrlen=%d]\n",
			
			eh->ether_shost[0], eh->ether_shost[1], eh->ether_shost[2],
			eh->ether_shost[3], eh->ether_shost[4], eh->ether_shost[5],
			
			eh->ether_dhost[0], eh->ether_dhost[1], eh->ether_dhost[2],
			eh->ether_dhost[3], eh->ether_dhost[4], eh->ether_dhost[5],
			
			eh->ether_type,
			rx,
			bh->bh_caplen,
			bh->bh_datalen,
			((struct bpf_hdr *) pbuf)->bh_hdrlen
		);
		
		/*
		 * length checks:
		 *   caplen == datalen
		 *   rx == caplen + hdrlen == datalen + hdrlen
		 */
		/* one line copy:
		 *
		 */
		DBG_INFO(printf("\nmemcpy --->\n");)
		//memcpy(packet, pbuf + ((struct bpf_hdr *) pbuf)->bh_hdrlen,  ((struct bpf_hdr *) pbuf)->bh_caplen);
		(void) memcpy(packet, pbuf + bh->bh_hdrlen, bh->bh_caplen);
		DBG_INFO(printf("\nmemcpy <---\n");)
		rx = bh->bh_caplen;
		DBG_INFO(printf("\nbh_caplen0 == %d %d\n",((struct bpf_hdr *) pbuf)->bh_caplen, bh->bh_caplen );)
		DBG_INFO(printf("\npbuf += --->\n");)
		//pbuf += BPF_WORDALIGN(((struct bpf_hdr *) pbuf)->bh_hdrlen + ((struct bpf_hdr *) pbuf)->bh_caplen);
		pbuf += BPF_WORDALIGN(bh->bh_hdrlen + bh->bh_caplen);
		DBG_INFO(printf("\npbuf += <---\n");)
		
		// memcpy(packet, pbuf + bh->bh_hdrlen, bh->bh_caplen);
		//pbuf += BPF_WORDALIGN(bh->bh_hdrlen + bh->bh_caplen);
	}
	
	DBG_INFO(printf("\nbh_caplen == %d %d\n",((struct bpf_hdr *) pbuf)->bh_caplen, bh->bh_caplen );)
	
	DBG_INFO(printf("\nfree(mbuf) --->\n");)
	free(mbuf);
	DBG_INFO(printf("\nfree(mbuf) <---\n");)
	
	LOG_OUT;
	
	//return bh->bh_caplen;
	return rx;
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

