
/* kernel module things */
#include <linux/kernel.h>
#include <linux/module.h>

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

#include <linux/if_ether.h>

/* ip functions: ip_hdrlen(..), ... */
#include <net/ip.h>

/* procfs obviously */
#include <linux/proc_fs.h>

/* copy_from_user() */
#include <asm/uaccess.h>

#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3], \
    ((unsigned char *)&addr)[4], \
    ((unsigned char *)&addr)[5]

static unsigned char mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

struct sk_buff *sock_buff;

/* net filter hook option struct */
struct nf_hook_ops nfho;
/* UDP header struct */
struct udphdr *udp_header;
/* IP header struct */
struct iphdr *ip_header;
/* ICMP header struct */
struct icmphdr *icmp_header;

struct ethhdr *eth_header;

#define skb_filter_name "skb_filter"

static struct proc_dir_entry *skb_filter;

static int filter_value = 0;

unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	sock_buff = skb;
	
	/* skb_mac_header(..) for Ethernet frame ? */
	eth_header = (struct ethhdr *) skb_mac_header(sock_buff);
	ip_header = (struct iphdr *) skb_network_header(sock_buff);
	
	if (!sock_buff) {
		return NF_ACCEPT;
	}
	
	//printk(KERN_INFO "filter: (%02X:%02X:%02X:%02X:%02X:%02X)\n", NIPQUAD(mac));
	
	if (eth_header->h_dest && eth_header->h_source) {
//			printk(KERN_INFO "SRC: (%02X:%02X:%02X:%02X:%02X:%02X) --> DST: (%02X:%02X:%02X:%02X:%02X:%02X)\n",
//				NIPQUAD(eth_header->h_dest), NIPQUAD(eth_header->h_source));
		if (!memcmp(eth_header->h_dest, mac, 6)) {
			printk(KERN_INFO "SRC: (%02X:%02X:%02X:%02X:%02X:%02X) --> DST: (%02X:%02X:%02X:%02X:%02X:%02X)\n",
				NIPQUAD(eth_header->h_source), NIPQUAD(eth_header->h_dest));
		}
	}
	
	if (ip_header->protocol == IPPROTO_UDP) {
		
		udp_header = (struct udphdr *)(skb_transport_header(sock_buff) + ip_hdrlen(sock_buff));
		if (udp_header) {
			//printk(KERN_INFO "SRC: (%u.%u.%u.%u):%d --> DST: (%u.%u.%u.%u):%d\n", NIPQUAD(ip_header->saddr), ntohs(udp_header->source), NIPQUAD(ip_header->daddr), ntohs(udp_header->dest));
//			printk(KERN_INFO "SRC: (%pI4):%d --> DST: (%pI4):%d\n", (&ip_header->saddr), ntohs(udp_header->source), (&ip_header->daddr), ntohs(udp_header->dest));
		} else {
			return NF_ACCEPT;
		}
		
		/* leagacy macro :
		- "%u.%u.%u.%u", NIPQUAD(inet_sk(sk)->inet_daddr));
		+ "%pI4", &inet_sk(sk)->inet_daddr); 
		*/
	}
	
	if (ip_header->protocol == IPPROTO_ICMP) {
//		printk(KERN_INFO "---------- ICMP -------------\n");
		icmp_header = (struct icmphdr *)(skb_transport_header(sock_buff) + ip_hdrlen(sock_buff));
		if (icmp_header) {
			//printk(KERN_INFO "SRC: (%u.%u.%u.%u) --> DST: (%u.%u.%u.%u)\n",NIPQUAD(ip_header->saddr),NIPQUAD(ip_header->daddr));
//			printk(KERN_INFO "SRC: (%pI4) --> DST: (%pI4)\n", (&ip_header->saddr), (&ip_header->daddr));
//			printk(KERN_INFO "ICMP type: %d - ICMP code: %d\n", icmp_header->type, icmp_header->code);
		} else {
			return NF_ACCEPT;
		}
	}
	
	return NF_ACCEPT;
	//return filter_value == 0 ? NF_ACCEPT : NF_ACCEPT;
}

int skb_read(char *page, char **start, off_t off, int count, int *eof, void *data)
{
	int len;
	
	if (off > 0) {
		*eof = 1;
		return 0;
	}
	
	if (count < sizeof(int)) {
		*eof = 1;
		return -ENOSPC;
	}
	
	/* copy to userspace */
	memcpy(page, &filter_value, sizeof(int));
	len = sizeof(int);
	
	return len;
}

int skb_write(struct file *file, const char *buffer, unsigned long len, void *data)
{
	unsigned char userData;
	
	if (len > PAGE_SIZE || len < 0) {
		printk(KERN_INFO "SKB System: cannot allow space for data\n");
		return -ENOSPC;
	}
	
	/* write data to the buffer */
	if (copy_from_user(&userData, buffer, 1)) {
		printk(KERN_INFO "SKB System: cannot copy data from userspace. D'OH!\n");
		return -EFAULT;
	}
	
	filter_value = simple_strtol(&userData, NULL, 10);
	
	return len;
}

int init_module()
{
	struct proc_dir_entry proc_root;
	int ret = 0;
	
	skb_filter = create_proc_entry(skb_filter_name, 0644, NULL);
	
	/* if proc entry can't be created */
	if (skb_filter == NULL) {
		ret = -ENOMEM;
		if (skb_filter) {
			remove_proc_entry( skb_filter_name, &proc_root);
		}
		printk(KERN_INFO "SKB Filter: Could not allocate memory.\n");
		goto error;
	} else {
		skb_filter->read_proc = skb_read;
		skb_filter->write_proc = skb_write;
		//skb_filter->owner = THIS_MODULE;
	}
	
	/* netfilter hook information:
	 * specify where and when we get the SKB
	 */
	nfho.hook = hook_func;
	nfho.hooknum = NF_IP_PRE_ROUTING;
	nfho.pf = PF_INET;
	nfho.priority = NF_IP_PRI_FIRST;
	
	nf_register_hook(&nfho);
	
	printk(KERN_INFO "Registering SK Parse Module\n");
	
	error:
	
	return ret;
}

void cleanup_module()
{
	nf_unregister_hook(&nfho);
	
	if (skb_filter) {
		remove_proc_entry(skb_filter_name, NULL);
	}
	
	printk(KERN_INFO "Unregistered the SK Parse Module\n");
}

MODULE_AUTHOR("ia");
MODULE_DESCRIPTION("netfilter demo module");
MODULE_LICENSE("GPL");

