
#ifndef _API_NT_H_
#define _API_NT_H_

/* includes and defines */

#define WIN32_LEAN_AND_MEAN

#if ( ( defined(__MINGW32__) ) || ( defined(__MINGW64__) ) )
	#define _WIN32_WINNT 0x501
	#define  MINGW       1
#else
	#pragma comment(lib, "ws2_32.lib")
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>

#ifndef _WIN32_WINNT
	#define _WIN32_WINNT 0x601
#endif

/* *** */

/* custom WIN32 specific data types */

struct thread_data {
	cnct_socket_t *socket;
	socket_t sd;
	int (*cb)(cnct_socket_t *, socket_t);
};

/* *** */

/* custom WIN32 specific functions */

static DWORD WINAPI cnct_socket_request(void *data)
{
	(*((struct thread_data *) data)->cb) (
			(((struct thread_data *) data)->socket),
			(((struct thread_data *) data)->sd)
	);
	return 0;
}

/* *** */

#endif /* _API_NT_H_ */

