
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

#endif /* _API_NT_H_ */

