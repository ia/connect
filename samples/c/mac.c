
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, const char *argv[])
{
	int mac_str_len = 18;
	char *mac_src = malloc(mac_str_len);
	if (!mac_src) {
		perror("malloc");
		return 1;
	}
	
	memset(mac_src, '\0', mac_str_len);
	memcpy(mac_src, "4c:72:b9:42:ed:d1\0", mac_str_len);
	
	//char *mac_dst = "00:25:00:d1:58:96\0";

	const char *delim = ":";

	char *p = NULL;
	char *ptr;
	int i = 0;

	char *token;
	
	token = strtok_r(mac_src, ":", &ptr);
	printf("%s\n", token);
	mac_src = NULL;
	token = strtok_r(mac_src, ":", &ptr);
	printf("%s\n", token);




	//for (i = 0; i < 6; i++) {
		//buf[i] = (unsigned char)strtoul( strtok_r(mac_src, ":", ptr), NULL, 16);
/*
	p = strtok_r(mac_src, delim, &ptr);
	printf("%d = %s\n", i, p);
	p = strtok_r(mac_src, delim, &ptr);
	printf("%d = %s\n", i, p);
*/	
	//char *p = strtok(mac_src, ":");

	//}
	
	return 0;
}
