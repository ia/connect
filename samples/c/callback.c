
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int cb2(int i, char *s)
{
	printf("cb2: i = %d\n", i);
	printf("cb2: s = %s\n", s);
	return 0;
}

int f2(int (*callback)(int, char *), int x)
{
	printf("f: x = %d\n", x);
	void *data = malloc(8);
	memset(data, 'a', 8);
	int cb_ret = (*callback)(1, data);
	printf("f: cb_ret = %d\n", cb_ret);
	return 0;
}

int cb(int c, int x)
{
	printf("cb: c = %d\n", c);
	printf("cb: x = %d\n", x);
	return 42;
}

int f(int (*callback)(int, int), int x)
{
	unsigned int c = 0xFF+1;
	int cb_ret = (*callback)(c, x);
	printf("f: cb_ret = %d\n", cb_ret);
	return 0;
}

int main(void)
{
	int x = 123;
	
	f(cb, x);
	f2(cb2, x);
	
	return 0;
}

