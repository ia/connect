
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#define NETLINK_USER   31

/* maximum payload size */
#define MAX_PAYLOAD  1024

int sock_fd;

struct sockaddr_nl src_addr, dest_addr;
struct nlmsghdr *nlh = NULL;
struct iovec iov;
struct msghdr msg;

int main(int argc, const char *argv[])
{
	sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
	
	if (sock_fd == -1) {
		perror("socket");
		return -1;
	}
	
	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid();
	
	/* interested in group 1<<0 */
	if (bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr)) != 0) {
		perror("bind");
		return -1;
	}
	
	memset(&dest_addr, 0, sizeof(dest_addr));
	memset(&dest_addr, 0, sizeof(dest_addr));
	
	dest_addr.nl_family = AF_NETLINK;
	/* kernel */
	dest_addr.nl_pid = 0;
	/* unicast */
	dest_addr.nl_groups = 0;
	
	nlh = (struct nlmsghdr *) malloc(NLMSG_SPACE(MAX_PAYLOAD));
	memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
	nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_flags = 0;
	
	strcpy(NLMSG_DATA(nlh), "Hello");
	
	iov.iov_base = (void *) nlh;
	iov.iov_len = nlh->nlmsg_len;
	
	msg.msg_name = (void *) &dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	
	printf("Sending message to kernel\n");
	
	sendmsg(sock_fd, &msg, 0);
	
	printf("Waiting for message from kernel\n");
	
	/* Read message from kernel */
	recvmsg(sock_fd, &msg, 0);
	
	printf(" Received message payload: %s\n", NLMSG_DATA(nlh));
	
	close(sock_fd);
	
	return 0;
}

