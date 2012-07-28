
#ifndef _API_NT_H_
#define _API_NT_H_

/* includes and defines */

#define WIN32_LEAN_AND_MEAN

#if ( ( defined(__MINGW32__) ) || ( defined(__MINGW64__) ) )
	#define _WIN32_WINNT 0x501
	#define MINGW 1
#else
	#pragma comment(lib, "ws2_32.lib")
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>

#ifndef _WIN32_WINNT
	#define _WIN32_WINNT 0x601
#endif

#define cnct_init()    cnct_init()
#define cnct_finish()  cnct_finish()

/* *** */

/* declarations */

static int cnct_init();
static int cnct_finish();

/* *** */


/* implementations */

static int cnct_init()
{
    LOG_IN;

    WORD wVersionRequested;
    WSADATA wsaData;
    int err;

    wVersionRequested = MAKEWORD(2, 2);

    err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0) {
        printf("WSAStartup failed with error: %d\n", err);
        return 1;
    }

    if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
        printf("Could not find a usable version of Winsock.dll\n");
        WSACleanup();
        return 1;
    }
    else {
        printf("The Winsock 2.2 dll was found okay\n");
    }

    //WSACleanup();
    DBG_ON(printf("on_debug check\n"));
    printf("build revision: %d\n", BUILDREV);
    DBG_ON(printf("_WIN32_WINNT: 0x%x\n", _WIN32_WINNT));

    LOG_OUT;
    return 0;
}

static int cnct_finish()
{
	LOG_IN;
	
	WSACleanup();
	
	LOG_OUT;
	return 0;
}


/* *** */

#endif /* _API_NT_H_ */

