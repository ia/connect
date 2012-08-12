
#pragma comment (lib, "ws2_32.lib")

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif


#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <stdio.h>


#define ERR(e) \
	printf("%s:%s failed: %d [%s@%ld]\n",__FUNCTION__,e,WSAGetLastError(),__FILE__,__LINE__)

#define CLOSESOCK(s) \
	if(INVALID_SOCKET != s) {closesocket(s); s = INVALID_SOCKET;}

#define DEFAULT_WAIT	30000

#define WS_VER	  0x0202

#define DEFAULT_PORT	12345

#define TST_MSG	 "0123456789abcdefghijklmnopqrstuvwxyz\0"

HANDLE hCloseSignal = NULL;

int __cdecl main()
{
	WSADATA wsd;
	INT nStartup = 0, nErr = 0, ret = 0;
	SOCKET lsock = INVALID_SOCKET, asock = INVALID_SOCKET;
	SOCKADDR_STORAGE    addr = {0};
	WSAPOLLFD           fdarray = {0};
	ULONG               uNonBlockingMode = 1;
	CHAR                buf[MAX_PATH] = {0};
	HANDLE              hThread = NULL;
	DWORD               dwThreadId = 0;
	
	nErr = WSAStartup(WS_VER,&wsd);
	if (nErr) {
		WSASetLastError(nErr);
		ERR("WSAStartup");
		exit(0);
	} else {
		nStartup++;
	}
	
	if (NULL == (hCloseSignal = CreateEvent(NULL, TRUE, FALSE, NULL))) {
		ERR("CreateEvent");
		exit(0);
	}
	
	/*
	if (NULL == (hThread = CreateThread(NULL, 0, ConnectThread, NULL, 0, &dwThreadId))) {
		ERR("CreateThread");
		//exit__leave;
	}
	*/
	
	addr.ss_family = AF_INET6;
	INETADDR_SETANY((SOCKADDR*)&addr);
	SS_PORT((SOCKADDR*)&addr) = htons(DEFAULT_PORT);
	
	if (INVALID_SOCKET == (lsock = socket(AF_INET6, SOCK_STREAM, 0))) {
		ERR("socket");
		exit(0);
	}
	
	if (SOCKET_ERROR == ioctlsocket(lsock, FIONBIO, &uNonBlockingMode)) {
		ERR("FIONBIO");
		exit(0);
	}
	
	if (SOCKET_ERROR == bind(lsock, (SOCKADDR*)&addr, sizeof (addr))) {
		ERR("bind");
		exit(0);
	}
	
	if (SOCKET_ERROR == listen(lsock, 100)) {
		ERR("listen");
		exit(0);
	}
	
	//Call WSAPoll for readability of listener (accepted)
	
	fdarray.fd = lsock;
	fdarray.events = POLLRDNORM;
	
	if (SOCKET_ERROR == (ret = WSAPoll(&fdarray, 1, DEFAULT_WAIT))) {
		ERR("WSAPoll");
		exit(0);
	}
	
	if (ret) {
		if (fdarray.revents & POLLRDNORM) {
			printf("Main: Connection established.\n");
			
			if (INVALID_SOCKET == (asock = accept(lsock, NULL, NULL))) {
				ERR("accept");
				__leave;
			}
			
			if (SOCKET_ERROR == (ret = recv(asock, buf, sizeof(buf), 0))) {
				ERR("recv");
				//__leave;
			} else {
				printf("Main: recvd %d bytes\n",ret);
			}
		}
	}
	
	//Call WSAPoll for writeability of accepted
	
	fdarray.fd = asock;
	fdarray.events = POLLWRNORM;
	
	if (SOCKET_ERROR == (ret = WSAPoll(&fdarray, 1, DEFAULT_WAIT))) {
		ERR("WSAPoll");
		// exit
	}
	
	if (ret) {
		if (fdarray.revents & POLLWRNORM) {
			if (SOCKET_ERROR == (ret = send(asock, TST_MSG, sizeof(TST_MSG), 0))) {
				ERR("send");
				// exit
			} else {
				printf("Main: sent %d bytes\n",ret);
			}
		}
	}
	
	//SetEvent(hCloseSignal);
	
	//WaitForSingleObject(hThread,DEFAULT_WAIT);
	
	/* clean up before exit */
	
	CloseHandle(hCloseSignal);
	CloseHandle(hThread);
	CLOSESOCK(asock);
	CLOSESOCK(lsock);
	
	if (nStartup) {
		WSACleanup();
	}
	
	return 0;
	
}

