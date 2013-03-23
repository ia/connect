
#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>

/*
http://www.bashguru.com/2010/01/shell-colors-colorizing-shell-scripts.html
http://www.linuxselfhelp.com/howtos/Bash-Prompt/Bash-Prompt-HOWTO-6.html
https://wiki.archlinux.org/index.php/Color_Bash_Prompt
http://tldp.org/HOWTO/Bash-Prompt-HOWTO/x329.html
*/

#define RED          "\033[1;32;41m"
#define GREEN_NOBG   "\033[1;32;1m"
#define GREEN        "\033[5;30;42m"
#define OLDCOLOR     "\033[0;0;0m"

int (*red)(const char *fmt, ...);
int (*green)(const char *fmt, ...);

int r_pr_(const char *fmt, ...)
{
	va_list ar; int i;
	printf(RED);
	va_start(ar, fmt);
	i = vprintf(fmt, ar);
	va_end(ar);
	printf(OLDCOLOR "\n");
	return i;
}

int g_pr_(const char *fmt, ...)
{
	va_list ar; int i;
	printf(GREEN);
	va_start(ar, fmt);
	i = vprintf(fmt, ar);
	va_end(ar);
	printf(OLDCOLOR "\n");
	return i;
}

int main()
{
	if (isatty(STDOUT_FILENO)) {
		printf(RED "This is a TTY! " GREEN "Output may be colorized!" OLDCOLOR "\n");
	} else {
		printf("This is pipe, no colors!\n");
	}
	
	if (isatty(STDOUT_FILENO)) { // make color output in tty
		red = r_pr_; green = g_pr_;
	} else { // no colors in case of pipe
		red = printf; green = printf;
	}
	
	red("red text\n");
	
	green("green text\n");
	
	return 0;
}

