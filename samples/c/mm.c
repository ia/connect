
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#include <linux/ip.h>
#include <linux/if_ether.h>

struct demo_st {
	__u16 len;
	unsigned char *data;
	unsigned char *payload;
} __attribute__((packed));

static inline unsigned char *get_data(struct demo_st *st)
{
	//return st + st->len;
	printf("inline: %02X\n", *((unsigned char *) st + 11));
	return &(*((unsigned char *) st + sizeof(__u16)));
	//return (unsigned char *) st + st->len;
}

static inline unsigned char *get_payload(struct demo_st *st)
{
	//return st + st->len;
//	printf("inline: %02X\n", *((unsigned char *) st + 11));
	return &(*((unsigned char *) st + sizeof(__u16) + st->len));
	//return (unsigned char *) st + st->len;
}

int main(int argc, const char *argv[])
{
	int size = 32;
	void *p = malloc(size);
	__u16 l = 0x0EAB;
	printf("size: %d\n", sizeof(l));
	printf("v1: %02X\n", *((unsigned char *) &l));
	printf("v2: %02X\n", *((unsigned char *) &l+1));
	
	memset(p, 0xFF, size);
	
	printf("hexx: %02X\n", *((unsigned char *) p+5));
	
	char *msg = "data1234anotherData\0";
	__u16 s = strlen(msg) + 1;
	memcpy(p, &s, sizeof(__u16));
	memcpy(p+sizeof(__u16), msg, s);

	char *pld = "payload\0";

	memcpy(p+sizeof(__u16) + s, pld, strlen(pld) + 1);
	
	struct demo_st *st = (struct demo_st *) p;
	printf("len: %02X\n", st->len);
	
//	printf("data: %02X \n", st->data);

	printf("data: %s\n", get_data(st));
	printf("pld: %s\n", get_payload(st));

//	printf("data[0]: %02X \n", *((unsigned char *) st->data) );
	
	free(p);
	
	return 0;
}

