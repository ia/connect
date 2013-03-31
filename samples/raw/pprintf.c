
/*
p_acket printf PoC implementation
*/

#include <stdio.h>
#include <stdarg.h>

int pprintf(unsigned char *packet, int len, char *fmt, ...)
{
	va_list ap;
	char *sval;
	int ival;
	double dval;
	unsigned u;
	int mac, ip, port, in, in_mac, in_ip, in_port;
	mac = ip = port = in = in_mac = in_ip = in_port = 0;
	va_start(ap,fmt);
	char *p = NULL;
	for (p = fmt; *p; p++) {
		switch (*p) {
			case '%':
				if (!in) {
					in = 1;
				} else if (in) {
					putchar('%');
					putchar('%');
					in = 0;
				}
				break;
			case 'm':
				if (in) {
					in_mac = 1;
				} else {
					putchar('m');
				}
				break;
			case 'i':
				if (in_mac) {
					putchar('%');
					putchar('m');
					in_mac = 0;
					in = 0;
				}
				if (in) {
					in_ip = 1;
				} else {
					putchar('i');
				}
				break;
			case 'p':
				if (in_mac) {
					putchar('%');
					putchar('m');
					in_mac = 0;
					in = 0;
				}
				if (in_ip) {
					putchar('%');
					putchar('i');
					in_ip = 0;
					in = 0;
				}
				if (in) {
					in_port = 1;
				} else {
					putchar('p');
				}
				break;
			case 'd':
				if (in_mac) {
					printf("MAC_DST");
					in = 0;
					in_mac = 0;
				}
				if (in_ip) {
					printf("IP_DST");
					in = 0;
					in_ip = 0;
				}
				if (in_port) {
					printf("PORT_DST");
					in = 0;
					in_port = 0;
				}
				if (in) {
					putchar('%');
					putchar('d');
					in = 0;
				}
				break;
			case 's':
				if (in_mac) {
					printf("MAC_SRC");
					in = 0;
					in_mac = 0;
				}
				if (in_ip) {
					printf("IP_SRC");
					in = 0;
					in_ip = 0;
				}
				if (in_port) {
					printf("PORT_SRC");
					in = 0;
					in_port = 0;
				}
				if (in) {
					for (sval = va_arg(ap, char *); *sval; sval++) {
						putchar(*sval);
					}
					/*
					putchar('%');
					putchar('s');
					*/
					in = 0;
				}
				break;
			default:
				if (in) {
					putchar('%');
					in = 0;
				}
				if (in_ip) {
//					putchar('%');
					putchar('i');
					in_ip = 0;
					in = 0;
				}
				if (in_mac) {
//					putchar('%');
					putchar('m');
					in_mac = 0;
					in = 0;
				}
	/*			if (in_ip) {
					putchar('i');
					in_ip = 0;
					in = 0;
				}
	*/			putchar(*p);
				break;
		}
	}
    va_end(ap);
	
}

int main(int argc, char const* argv[])
{
	pprintf(NULL, 0, "%s %d %a a % %ms %md %is %id %ma %mi %im %pd %ps %s\n", "test line", "end line");
	printf("%q", 10);
	return 0;
}

