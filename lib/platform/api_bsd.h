
#ifndef _API_BSD_H_
#define _API_BSD_H_

/* includes */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

/* *** */

/* defines */

#define cnct_init()
#define cnct_finish()

/* *** */

/* declarations */

static int socket_set_nonblock(socket_t sd);

/* *** */


/* implementations */

static int socket_set_nonblock(socket_t sd)
{
	LOG_IN;
	
	int flags, s;
	
	flags = fcntl(sd, F_GETFL, 0);
	if (flags == -1) {
		perror("fcntl");
		return -1;
	}
	
	flags |= O_NONBLOCK;
	s = fcntl(sd, F_SETFL, flags);
	if (s == -1) {
		perror("fcntl");
		return -1;
	}
	
	LOG_OUT;
	return 0;
}

/* *** */

#endif /* _API_BSD_H_ */

