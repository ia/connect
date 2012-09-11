
#include "../connect.h"

int cnct_filter_bpf(socket_t sd)
{
	struct sock_filter bpf[] = { CNCT_BPF_PCKT };
	struct sock_fprog fprog;
	
	fprog.len = 1;
	fprog.filter = bpf;
	
	if (setsockopt(sd, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog)) < 0) {
		perror("setsockopt");
		cnct_socket_close(sd);
		return -1;
	}
	
	return 0;
}

