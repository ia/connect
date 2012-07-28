
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <net/if.h>
#include <linux/rtnetlink.h>

#include <unistd.h>
#include <arpa/inet.h>

#define BUFSIZE 8192

struct route_info
{
	struct in_addr dstAddr;
	struct in_addr srcAddr;
	struct in_addr gateWay;
	char ifName[IF_NAMESIZE];
};


int readNlSock(int sockFd, char *bufPtr, int seqNum, int pId)
{
	struct nlmsghdr *nlHdr;
	int readLen = 0, msgLen = 0;
	
	do {
		/* Recieve response from the kernel */
		if ((readLen = recv(sockFd, bufPtr, BUFSIZE - msgLen, 0)) < 0) {
			perror("SOCK READ: ");
			return -1;
		}
		
		nlHdr = (struct nlmsghdr *)bufPtr;
		
		/* Check if the header is valid */
		if ((NLMSG_OK(nlHdr, readLen) == 0) || (nlHdr->nlmsg_type == NLMSG_ERROR)) {
			perror("Error in recieved packet");
			return -1;
		}
		
		/* Check if the its the last message */
		if (nlHdr->nlmsg_type == NLMSG_DONE) {
			break;
		} else {
			/* Else move the pointer to buffer appropriately */
			bufPtr += readLen;
			msgLen += readLen;
		}
		
		/* Check if its a multi part message */
		if ((nlHdr->nlmsg_flags & NLM_F_MULTI) == 0) {
			/* return if its not */
			break;
		}
	} while ((nlHdr->nlmsg_seq != seqNum) || (nlHdr->nlmsg_pid != pId));
	
	return msgLen;
}

/* parse the route info returned */
void parseRoutes(struct nlmsghdr *nlHdr, struct route_info *rtInfo)
{
	struct rtmsg *rtMsg;
	struct rtattr *rtAttr;
	int rtLen;
	
	rtMsg = (struct rtmsg *)NLMSG_DATA(nlHdr);
	
	/* If the route is not for AF_INET or does not belong to main routing table then return */
	if ((rtMsg->rtm_family != AF_INET) || (rtMsg->rtm_table != RT_TABLE_MAIN)) {
		return;
	}
	
	/* get the rtattr field */
	rtAttr = (struct rtattr *)RTM_RTA(rtMsg);
	rtLen = RTM_PAYLOAD(nlHdr);
	
	for ( ; RTA_OK(rtAttr,rtLen); rtAttr = RTA_NEXT(rtAttr,rtLen)) {
		switch(rtAttr->rta_type) {
			case RTA_OIF:
				if_indextoname(*(int *)RTA_DATA(rtAttr), rtInfo->ifName);
				break;
			case RTA_GATEWAY:
				memcpy(&rtInfo->gateWay, RTA_DATA(rtAttr), sizeof(rtInfo->gateWay));
				break;
			case RTA_PREFSRC:
				memcpy(&rtInfo->srcAddr, RTA_DATA(rtAttr), sizeof(rtInfo->srcAddr));
				break;
			case RTA_DST:
				memcpy(&rtInfo->dstAddr, RTA_DATA(rtAttr), sizeof(rtInfo->dstAddr));
				break;
		}
	}
	
	return;
}

// meat
int get_gatewayip(char *gatewayip, socklen_t size)
{
	int found_gatewayip = 0;
	
	struct nlmsghdr *nlMsg;
	struct rtmsg *rtMsg;
	struct route_info *rtInfo;
	char msgBuf[BUFSIZE]; // pretty large buffer
	
	int sock, len, msgSeq = 0;
	
	/* Create Socket */
	if ((sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) < 0) {
		perror("Socket Creation: ");
		return(-1);
	}
	
	/* Initialize the buffer */
	memset(msgBuf, 0, BUFSIZE);
	
	/* point the header and the msg structure pointers into the buffer */
	nlMsg = (struct nlmsghdr *)msgBuf;
	rtMsg = (struct rtmsg *)NLMSG_DATA(nlMsg);
	
	/* Fill in the nlmsg header*/
	nlMsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)); // Length of message
	nlMsg->nlmsg_type = RTM_GETROUTE; // Get the routes from kernel routing table
	
	nlMsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST; // The message is a request for dump
	nlMsg->nlmsg_seq = msgSeq++; // Sequence of the message packet
	nlMsg->nlmsg_pid = getpid(); // PID of process sending the request
	
	/* Send the request */
	if (send(sock, nlMsg, nlMsg->nlmsg_len, 0) < 0) {
		fprintf(stderr, "Write To Socket Failed...\n");
		return -1;
	}
	
	/* Read the response */
	if ((len = readNlSock(sock, msgBuf, msgSeq, getpid())) < 0) {
		fprintf(stderr, "Read From Socket Failed...\n");
		return -1;
	}
	
	/* Parse and print the response */
	rtInfo = (struct route_info *)malloc(sizeof(struct route_info));
	
	for ( ; NLMSG_OK(nlMsg,len); nlMsg = NLMSG_NEXT(nlMsg,len)) {
		memset(rtInfo, 0, sizeof(struct route_info));
		parseRoutes(nlMsg, rtInfo);
		
		// Check if default gateway
		if (strstr((char *)inet_ntoa(rtInfo->dstAddr), "0.0.0.0")) {
			// copy it over
			inet_ntop(AF_INET, &rtInfo->gateWay, gatewayip, size);
			found_gatewayip = 1;
			break;
		}
	}
	
	free(rtInfo);
	close(sock);
	
	return found_gatewayip;
}

int main(int argc, char const* argv[])
{
	char *gatewayip = malloc(INET6_ADDRSTRLEN);
	memset(gatewayip, '\0', INET6_ADDRSTRLEN);
	
	if (get_gatewayip(gatewayip, INET6_ADDRSTRLEN)) {
		printf("gateway: %s\n", gatewayip);
	}
	
	return 0;
}

