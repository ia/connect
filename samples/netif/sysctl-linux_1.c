
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/sysctl.h>

int main(int argc, char const* argv[])
{
	/*
	int set = 0;

	int ip_forward[] = {CTL_NET,NET_IPV4,NET_IPV4_FORWARD};
	int curr;
	size_t curr_size = sizeof(curr);
	
	int result = sysctl(ip_forward,3,&curr,&curr_size,0,0);

	printf("result: %d\n", result);
	printf("curr  : %d\n", curr);
	
	int on = 1;
	int off = 0;
	if (set && !curr) {
		result = sysctl(ip_forward, 3, &curr, &curr_size, &on, &curr_size);
		printf("ipv4_forward: on\n");
	} else if (!set && curr) {
		result = sysctl(ip_forward, 3, &curr, &curr_size, &off, &curr_size);
		printf("ipv4_forward: off\n");
	} else {
		printf("skip\n");
	}
	
	if (!result) {
		perror("sysctl");
	}
	*/
	int ip_forward[] = {CTL_NET,NET_IPV4,NET_IPV4_FORWARD};
	int new_value = 1;
	size_t new_size = sizeof(new_value);
	
	int result = sysctl(ip_forward,3,0,0,&new_value,new_size);
	if(result == -1){
		return -1;
	}

	return 0;
}

