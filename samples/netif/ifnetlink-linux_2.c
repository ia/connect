
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <unistd.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

struct {
    struct nlmsghdr  nh;
    struct ifinfomsg ifi;
    char             attrbuf[512];
} req;

/* change MTU */
int main(int argc, const char *argv[])
{
	struct rtattr *rta;
	unsigned int mtu = 1500;
	
	int rtnetlink_sk = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	
	memset(&req, 0, sizeof(req));
	req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nh.nlmsg_flags = NLM_F_REQUEST;
	req.nh.nlmsg_type = RTM_GETLINK; //  RTM_NEWLINK;
	req.ifi.ifi_family = AF_UNSPEC;
	req.ifi.ifi_index = INTERFACE_INDEX;
	req.ifi.ifi_change = 0xffffffff; /* ??? */
	rta = (struct rtattr *)(((char *) &req) + NLMSG_ALIGN(req.nh.nlmsg_len));
	rta->rta_type = IFLA_MTU;
	rta->rta_len = sizeof(unsigned int);
	req.nh.nlmsg_len = NLMSG_ALIGN(req.nh.nlmsg_len) + RTA_LENGTH(sizeof(mtu));
	memcpy(RTA_DATA(rta), &mtu, sizeof(mtu));
	send(rtnetlink_sk, &req, req.nh.nlmsg_len, 0);
	
	return 0;
}

