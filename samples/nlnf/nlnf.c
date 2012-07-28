
#define MODULE_NAME "nlnf"

#define NETLINK_NETFILTER_NG NETLINK_USERSOCK

#ifndef RELEASE
	
	/* helper defines for debugging info output */
	
	#define DEBUG 1
	#define DBG_ON(action) \
		action
	
	#define DBG_INFO(action) \
		printk(KERN_INFO "%s: %s: %d\n", MODULE_NAME, __func__, __LINE__); action
	#define DBG_KINFO(msg) \
		printk(KERN_INFO "%s: %s\n", MODULE_NAME, msg);
	#define DBG_KALERT(msg) \
		printk(KERN_ALERT "%s: %s\n", MODULE_NAME, msg);
	
	#define DBG_MSG_KINFO(msg, value) \
		printk(KERN_INFO "%s: %s: %s\n", MODULE_NAME, msg, value);
	
	#define DBG_PRINT(fmt, ...) printf(fmt ##__VA_ARGS__)
	
	#define LOG_IN \
		printk(KERN_INFO "%s: ==== >>>> %s: %d\n",  MODULE_NAME, __func__, __LINE__);
	#define LOG_OUT \
		printk(KERN_INFO "%s: <<<< ==== %s: %d\n",  MODULE_NAME, __func__, __LINE__);
	
	#define PRINT_L(value) \
		printk(KERN_INFO "%s:\t" #value " = %ld\n", MODULE_NAME, value);
	#define PRINT_S(value) \
		printk(KERN_INFO "%s:\t" #value " = %s\n",  MODULE_NAME, value);
	#define PRINT_D(value) \
		printk(KERN_INFO "%s:\t" #value " = %d\n",  MODULE_NAME, value);
	
#elif defined RELEASE
	
	/* disable debug helper defines in RELEASE version */
	
	#undef DEBUG
	#define DBG_ON
	#define DBG_INFO
	#define DBG_KINFO
	#define DBG_KALERT
	#define DBG_PRINT
	#define LOG_IN
	#define LOG_OUT
	#define PRINT_L
	#define PRINT_S
	#define PRINT_D
	
#endif


/* generic routine helper defines */

#define ACCEPT_ON_NULL(ptr) \
	if (!ptr) { return NF_ACCEPT; }

#define ACCEPT_ON_NULL_INFO(ptr, msg) \
	if (!ptr) { printk(KERN_INFO "%s: %s: %d: %s\n", MODULE_NAME, __func__, __LINE__, msg); return NF_ACCEPT; }

#define MSG_KINFO(msg) \
	printk(KERN_INFO "%s: %s\n", MODULE_NAME, msg);

#define MSG_KERR(msg) \
	printk(KERN_ERR "%s: %s\n", MODULE_NAME, msg);

#define MSG_KALERT(msg) \
	printk(KERN_ALERT "%s: %s\n", MODULE_NAME, msg);

/* *** includes *** */

/* kernel module things */
#include <linux/kernel.h>
#include <linux/module.h>

/* netlink socket subsystem */
#include <linux/netlink.h>

/* netfilter subsystem */
#include <linux/netfilter.h>
/* workaround for getting NF_IP_ values */
#undef __KERNEL__
#include <linux/netfilter_ipv4.h>
#define __KERNEL__

/* sk_buff routine */
#include <linux/skbuff.h>

/* proto struct headers */
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>

/* ethernet header routine */
#include <linux/if_ether.h>

/* ip functions: ip_hdrlen(..), ... */
#include <net/ip.h>
/* kernel socket routine */
#include <net/sock.h>

/* procfs obviously */
#include <linux/proc_fs.h>

#include <linux/slab.h>

/* copy_from_user() */
#include <asm/uaccess.h>

#include "nlnf.h"

#define MAX_PKT_SIZE 4096

/* Hardware address - from hex to print */
#define MAC_HTOP(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3], \
    ((unsigned char *)&addr)[4], \
    ((unsigned char *)&addr)[5]

/* *** global variables *** */

/* this looks like crap */
//struct sk_buff *skb_out;

/* netlink socket for kernel/user space */
struct sock *nlsk = NULL;

/* netlink socket pid */
static int nlsk_pid = 0;

/* netfilter hook option struct */
struct nf_hook_ops nfho;

/* should we dumping packages? */
static int filter = 0;

struct nlnf_pf *pf;
void *pkt; /* struct nlnf_pkt * */

static unsigned char mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

/* *** *** *** */

/*
static inline unsigned char *skb_data(const struct sk_buff *skb)
{
	return skb->head + skb->len;
}
*/

static void nlnf_pf_out_legacy(unsigned char *raw)
{
	LOG_IN;
	
	struct nlmsghdr *nlh_out;
	struct sk_buff *skbf_out;
	unsigned int len;
	
	len = strlen(raw);
	
	skbf_out = nlmsg_new(len, 0);
	if (!skbf_out) {
		MSG_KERR("can't allocate sk_buff");
		LOG_OUT;
		return;
	}
	
	nlh_out = nlmsg_put(skbf_out, 0, 0, NLMSG_DONE, len , 0);
	NETLINK_CB(skbf_out).dst_group = 0;
	
	memcpy(nlmsg_data(nlh_out), raw, len);
	
	if (nlmsg_unicast(nlsk, skbf_out, nlsk_pid) < 0) {
		DBG_KINFO("no process in user space for receiving netlink message");
		filter = 0;
		DBG_KINFO("resetting filter since no one need it");
	}
	
	LOG_OUT;
	return;
}

static void nlnf_pf_out(void *pkt, unsigned int len)
{
	LOG_IN;
	
	struct nlmsghdr *nlh_out;
	struct sk_buff *skbf_out;
//	unsigned int len;
	
//	len = sizeof()strlen(raw);
	
	skbf_out = nlmsg_new(len, 0);
	if (!skbf_out) {
		MSG_KERR("can't allocate sk_buff");
		LOG_OUT;
		return;
	}
	
	nlh_out = nlmsg_put(skbf_out, 0, 0, NLMSG_DONE, len , 0);
	NETLINK_CB(skbf_out).dst_group = 0;
	
	memcpy(nlmsg_data(nlh_out), pkt, len);
	
	if (nlmsg_unicast(nlsk, skbf_out, nlsk_pid) < 0) {
		DBG_KINFO("no process in user space for receiving netlink message");
		filter = 0;
		DBG_KINFO("resetting filter since no one need it");
	}
	
	LOG_OUT;
	return;
}

static void nlnf_pf_set(struct sk_buff *skb_in)
{
	LOG_IN;
	
	struct nlmsghdr *nlh_in;
	struct sk_buff *skbf_in;
	int pid;
	int msg_len;
	//struct nlnf_pf *pf;
	
	char *msg = "syn/ack kernel socket";
	
	msg_len = strlen(msg);
	
	nlh_in = (struct nlmsghdr *) skb_in->data;
	
	/* pid of sending process */
	pid = nlh_in->nlmsg_pid;
	nlsk_pid = pid;
	
	pf = (struct nlnf_pf *) nlmsg_data(nlh_in);
	
	printk(KERN_INFO "%s: pf->filter: %d", MODULE_NAME, (pf->filter));
	if (pf->hw_addr_dest[0]) {
		printk(KERN_INFO "%s: pf->hw_addr_dest[0]: (%x)\n", MODULE_NAME, (pf->hw_addr_dest[0]));
	}
	
	if (pf->filter) {
		filter = 1;
	} else {
		filter = 0;
	}
	
	/* the following code just for sent back syn/ack in user space - can be removed */
	
	skbf_in = nlmsg_new(msg_len, 0);
	if (!skbf_in) {
		MSG_KERR("can't allocate sk_buff");
		LOG_OUT;
		return;
	}
	
	nlh_in = nlmsg_put(skbf_in, 0, 0, NLMSG_DONE, msg_len, 0);
	NETLINK_CB(skbf_in).dst_group = 0;
	
	strncpy(nlmsg_data(nlh_in), msg, msg_len);
	
	if (nlmsg_unicast(nlsk, skbf_in, pid) < 0) {
		MSG_KINFO("error on sending netlink message to user space");
	}
	
	LOG_OUT;
	
	return;
}

unsigned int nlnf_pf_get(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	LOG_IN;
	
	ACCEPT_ON_NULL(filter);
	/* ??? skb_out = skb; */
	ACCEPT_ON_NULL(skb);
	
	struct ethhdr *eth_header;
//	struct iphdr *ip_header;
//	struct icmphdr *icmp_header;
//	struct udphdr *udp_header;
	
//	struct nlnf_pkt *pkt;
	
	eth_header = (struct ethhdr *) skb_mac_header     (skb);
	
//	ip_header =  (struct iphdr  *) skb_network_header (skb);
	
	if (!pf) {
		MSG_KALERT("error: pf == NULL");
		LOG_OUT;
		return NF_ACCEPT;
	}
	
	if (!pf->hw_addr_dest) {
		MSG_KALERT("error: pf->hw_addr_dest == NULL");
		LOG_OUT;
		return NF_ACCEPT;
	}
	/*
	pkt = kmalloc(sizeof(struct nlnf_pkt), GFP_KERNEL);
	if (!pkt) {
		MSG_KALERT("error: pkt == NULL");
		LOG_OUT;
		return NF_ACCEPT;
	}
	*/
	printk(KERN_INFO "%s: pf->filter: %d", MODULE_NAME, (pf->filter));
	printk(KERN_INFO "%s: pf->hw_addr_dest[0]: (%02X)\n", MODULE_NAME, (pf->hw_addr_dest[0]));
	printk(KERN_INFO "%s: pf->hw_addr_dest[1]: (%02X)\n", MODULE_NAME, (pf->hw_addr_dest[1]));
	
	if (eth_header->h_dest && eth_header->h_source) {
//			printk(KERN_INFO "SRC: (%02X:%02X:%02X:%02X:%02X:%02X) --> DST: (%02X:%02X:%02X:%02X:%02X:%02X)\n",
//				MAC_HTOP(eth_header->h_source), MAC_HTOP(eth_header->h_dest));
		if (!memcmp(eth_header->h_source, pf->hw_addr_src, 6)) {
			printk(KERN_INFO "SRC: (%02X:%02X:%02X:%02X:%02X:%02X) --> DST: (%02X:%02X:%02X:%02X:%02X:%02X)\n",
				MAC_HTOP(eth_header->h_source), MAC_HTOP(eth_header->h_dest));
			/* sent back to user space */
			//memcpy(pf_out->eth_hdr, eth_header, sizeof(struct ethhdr));
			/*
			memcpy(pf_out->hw_addr_src, eth_header->h_source, 6);
			memcpy(pf_out->eth_hdr->h_source, eth_header->h_source, 6);
			???
			pf_out->filter = 210;
			printk(KERN_INFO "%s: memcpy ok\n", MODULE_NAME);
			nl_send_msg(pf_out);
			*/
		
	//		pkt = kmalloc(sizeof(struct nlnf_pkt), GFP_KERNEL);
		/*
			if (!pkt) {
				MSG_KALERT("error: pkt == NULL");
				LOG_OUT;
				return NF_ACCEPT;
			}
			memset(pkt, '\0', sizeof(struct nlnf_pkt));
			
			pkt->mac_hdr = kmalloc(strlen(skb_mac_header(skb)+2), GFP_KERNEL);
			memcpy(pkt->mac_hdr, skb_mac_header(skb), strlen(skb_mac_header(skb)));
			
			if (!pkt) {
				MSG_KALERT("error: pkt == NULL");
				LOG_OUT;
				return NF_ACCEPT;
			}
			*/
			
//			pkt->mac_hdr = skb_mac_header(skb);
			/*
			if (!pkt->mac_hdr) {
				MSG_KALERT("error: pkt->mac_hdr == NULL");
				LOG_OUT;
				return NF_ACCEPT;
			}
		*/
	//		printk(KERN_INFO "%s: strlen skb_mac_header: %d", MODULE_NAME, (strlen(skb_mac_header((skb)))));
	//		printk(KERN_INFO "%s: skb mac_len: %d", MODULE_NAME, (skb->mac_len));
//			nlnf_pf_out(pkt->mac_hdr, strlen(skb_mac_header(skb)) + 1);
//			nlnf_pf_out_legacy(pkt->mac_hdr); //, strlen(skb_mac_header(skb)));
//			nlnf_pf_out_legacy(skb_mac_header(skb));
			
		//	kfree(pkt->mac_hdr);
	//		kfree(pkt);
			

			/* another one try */
	//		memset(pkt, '\0', MAX_PKT_SIZE);
	//		memcpy(pkt, skb_mac_header(skb), strlen(skb_mac_header(skb)) - 1);
		//	strcpy(pkt, skb_mac_header(skb));
//			nlnf_pf_out(pkt, (skb->mac_len));
	//		nlnf_pf_out(pkt, strlen(skb_mac_header(skb)));
		//	nlnf_pf_out(pkt, strlen(pkt));
			//nlnf_pf_out(pkt, strlen(((struct nlnf_pkt *) pkt)->mac_hdr)) ; // skb_mac_header(skb)));
			//
			
			
			memset(pkt, '\0', MAX_PKT_SIZE);
			
			/* mac header packing */
			unsigned int mac_len_size = sizeof(__u16);
			
			memcpy(pkt, &(skb->mac_len), mac_len_size);
			memcpy(pkt + mac_len_size, skb_mac_header(skb), skb->mac_len);
			
			/* net header packing */
			unsigned int net_len_size = sizeof(u32);
			
			u32 net_len = skb_network_header_len(skb);
			printk(KERN_INFO "%s: net_len: %d", MODULE_NAME, net_len);
			printk(KERN_INFO "%s: net_len_size: %d", MODULE_NAME, net_len_size);
			printk(KERN_INFO "%s: net_hdr0: %02X", MODULE_NAME, skb_network_header(skb)[0]);
			printk(KERN_INFO "%s: net_hdr1: %02X", MODULE_NAME, skb_network_header(skb)[1]);
			printk(KERN_INFO "%s: skb->truesize: %d", MODULE_NAME, skb->truesize);
			printk(KERN_INFO "%s: skb->len: %d", MODULE_NAME, skb->len);
			printk(KERN_INFO "%s: skb->hdr_len: %d", MODULE_NAME, skb->hdr_len);
			printk(KERN_INFO "%s: skb->data_len: %d", MODULE_NAME, skb->data_len);
			printk(KERN_INFO "%s: skb->data0: %02X", MODULE_NAME, skb->data[0]);
			printk(KERN_INFO "%s: skb->data1: %02X", MODULE_NAME, skb->data[1]);
			memcpy(pkt + mac_len_size + skb->mac_len, &(net_len), net_len_size);
			memcpy(pkt + mac_len_size + skb->mac_len + net_len_size, skb_network_header(skb), net_len);
			
			nlnf_pf_out(pkt, mac_len_size + skb->mac_len + net_len_size + net_len);
			
			//nlnf_pf_out_legacy(skb_mac_header(skb));
			
		}
	}
//	kfree(pkt);
	LOG_OUT;
	return NF_ACCEPT;
}

/* init routine */
int init_module()
{
	LOG_IN;
	
	//pkt = kmalloc(sizeof(struct nlnf_pkt), GFP_KERNEL);
	pkt = kmalloc(MAX_PKT_SIZE, GFP_KERNEL);
	if (!pkt) {
		MSG_KALERT("error: can't allocate memory for packet");
		LOG_OUT;
		return -1;
	}
	/*
	pkt->eth_hdr = kmalloc(sizeof(struct ethhdr), GFP_KERNEL);
	if (!pf_out->eth_hdr) {
		MSG_KALERT("error: can't allocate memory for packet buffer");
		LOG_OUT;
		return -1;
	}
	*/
	
	/* netlink socket for communication with user space filter */
	nlsk = netlink_kernel_create(&init_net, NETLINK_NETFILTER_NG, 0, nlnf_pf_set, NULL, THIS_MODULE);
	if (!nlsk) {
		MSG_KALERT("error: can't create netlink socket");
		LOG_OUT;
		return -1;
	}
	
	DBG_KINFO("creating netlink socket");
	
	/* netfilter hook information: specify where and when we get the SKB */
	nfho.hook = nlnf_pf_get;
	nfho.hooknum = NF_IP_PRE_ROUTING;
	nfho.pf = PF_INET;
	nfho.priority = NF_IP_PRI_FIRST;
	
	nf_register_hook(&nfho);
	DBG_KINFO("creating netfilter hook");
	
	LOG_OUT;
	DBG_KINFO("insmod");
	
	return 0;
}

/* clean up routine */
void cleanup_module()
{
	LOG_IN;
	
	/* de-attaching hook function */
	nf_unregister_hook(&nfho);
	DBG_KINFO("removing netfilter hook");
	
	/* closing netlink kernel socket */
	netlink_kernel_release(nlsk);
	DBG_KINFO("closing netlink socket");
	
	LOG_OUT;
	DBG_KINFO("rmmod");
	
	return;
}

MODULE_AUTHOR("ia");
MODULE_DESCRIPTION("netlink/netfilter module");
MODULE_LICENSE("GPL");

