
#include "connect.h"

#define FLTR_PROTO_ETH 0x0
#define FLTR_PROTO_IP  0x1
#define FLTR_PROTO_TCP 0x2
#define FLTR_PROTO_UDP 0x3

#define STR "00:0C:29:B0:8F:C9"
#define HEX 0x000C29B08FC9

int convert_mac_hex2str(char *hex, char *str)
{
	return 0;
}

int print_mac(unsigned *packet, int len)
{
	int i;
	for (i = 0; i < len; i++) {
		printf("%02X", *((unsigned *) packet + i));
		if (i == 14) {
			printf("\n");
			break;
		} else {
			printf(" ");
		}
	}
	return 0;
}

//int convert_mac_str2hex(char *str1, char *hex)
int convert_mac_str2hex(void)
{
	/*
std::string mac = "00:00:12:24:36:4f";
unsigned u[6];
int c=sscanf(mac.c_str(),"%x:%x:%x:%x:%x:%x",u,u+1,u+2,u+3,u+4,u+5);
if (c!=6) raise_error("input format error");
uint64_t r=0;
for (int i=0;i<6;i++) r=(r<<8)+u[i];
 or:  for (int i=0;i<6;i++) r=(r<<8)+u[5-i];
*/
	const char *str = STR;
	unsigned u[6];
	int c = sscanf(str, "%x:%x:%x:%x:%x:%x", u, u + 1, u + 2, u + 3, u + 4, u + 5);
	if (c != 6) {
		printf("input format error\n");
	}
	
	uint64_t r = 0;
	int i = 0;
	for (i = 0; i < 6; i++) {
		r = (r << 8) + u[i];
	}
	
	printf("%02X\n", (char )u[0]);
	printf("%02X\n", u[1]);
	printf("%02X\n", u[2]);
	print_mac(u, 6);
	return 0;
}

int mac_src(char *packet, int proto)
{
	if (proto != FLTR_PROTO_ETH) {
		return -1;
	}
	
	
}

//int mac_dst

int main(int argc, const char *argv[])
{
	convert_mac_str2hex();
	return 0;
}

