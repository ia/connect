
/* Example of using sigaction() to setup a signal handler with 3 arguments
 * including siginfo_t.
 */

/* http://www.linuxprogrammingblog.com/all-about-linux-signals?page=3 */

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

void *data;

static void hdl(int sig, siginfo_t *siginfo, void *context)
{
	printf("\nSending PID: %ld, UID: %ld, SIG: %d\n", (long) siginfo->si_pid, (long) siginfo->si_uid, sig);
	if (sig == SIGINT) {
		printf("data: %s\n", data);
		printf("exit\n");
		exit(1);
	}
}

int main(int argc, char *argv[])
{
	struct sigaction act;
	
	memset (&act, '\0', sizeof(act));
	
	/* Use the sa_sigaction field because the handles has two additional parameters */
	act.sa_sigaction = &hdl;
	
	/* The SA_SIGINFO flag tells sigaction() to use the sa_sigaction field, not sa_handler. */
	act.sa_flags = SA_SIGINFO;
	
	if (sigaction(SIGTERM, &act, NULL) < 0) {
		perror ("sigaction");
		return 1;
	}
	
	data = malloc(4*1024);
	memset(data, '\0', 4*1024);
	strcpy(data, "data buffer");
	
	if (sigaction(SIGINT, &act, NULL) < 0) {
		perror ("sigaction");
		return 1;
	}
	
	while (1)
		sleep (1);
	
	return 0;
}

