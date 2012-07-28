
#include <stdio.h>

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
	return 0;
}

