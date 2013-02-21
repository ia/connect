
#if defined(KERNEL)

/* --------------------  kernel space routine  ----------------- */

#pragma message("SYS_NT: kernel space")

/*
Kernel space sniffer.
Guidelines used: Rootkits, subverting the windows kernel
 NT Rootkit
Made by: DiabloHorn
Purpose: Sniff data and filter it on text.
Thanks to: n0limit,BackBon3
*/

#pragma warning(disable:4700)

#define NDIS50 1

#include <stdio.h>
#include <string.h>
#include <ntddk.h>
#include <ndis.h>
#include <wdm.h>
#include "sys_nt.h"

struct timeval {
        long    tv_sec;         ///< seconds
        long    tv_usec;        ///< microseconds
};

const WCHAR deviceLinkBuffer[] = L"\\DosDevices\\myDevice1"; // Symlink for the device
const WCHAR deviceNameBuffer[] = L"\\Device\\myDevice1"; // Define the device

//const WCHAR deviceNameBuffer[] = L"\\Device\\PacketFilter";

PDEVICE_OBJECT g_device;

int packet_ready = 0;
int irp_request = 0;

unsigned char *packet = NULL;
size_t packet_size = 64 * 1024;

// packet = ExAllocatePool(NonPagedPool, (aHeaderBufferLen + aBufferLen));

/*
 * -- time management links:
 *  http://msdn.microsoft.com/en-us/library/windows/hardware/ff553068(v=vs.85).aspx
 *  http://msdn.microsoft.com/en-us/library/windows/hardware/ff545622(v=vs.85).aspx
 *  http://blogs.msdn.com/b/mikekelly/archive/2009/01/17/unix-time-and-windows-time.aspx
 *  http://curl.haxx.se/mail/lib-2005-01/0089.html
 *  http://drp.su/ru/driver_dev/07_07_9-10.htm
 */

int gettimeofday(struct timeval *dst)
{
	LARGE_INTEGER SystemTime;
	LARGE_INTEGER LocalTime;
	
	KeQuerySystemTime(&SystemTime);
	ExSystemTimeToLocalTime(&SystemTime, &LocalTime);
	
	dst->tv_sec  = (LONG) (LocalTime.QuadPart / 10000000 - 11644473600);
	dst->tv_usec = (LONG)((LocalTime.QuadPart % 10000000) / 10);
	
	return 0;
}

NTSTATUS OnOpen(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	DbgPrint("ndSniff OnOpen called\n");
	return STATUS_SUCCESS;
}

NTSTATUS OnClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	DbgPrint("ndSniff OnClose called\n");
	return STATUS_SUCCESS;
}

NTSTATUS OnRead(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	DbgPrint("ndSniff OnRead called\n");
	return STATUS_SUCCESS;
}

NTSTATUS OnWrite(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	DbgPrint("ndSniff OnWrite called\n");
	return STATUS_SUCCESS;
}

NTSTATUS OnIoControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	PIO_STACK_LOCATION IrpSl;
	ULONG CtlCode;
	PVOID pBuf = Irp->AssociatedIrp.SystemBuffer;
	PCHAR sayhello = "Hi! From kernelLand.";
	
	DbgPrint("ndSniff OnIoControl called\n");
	
	/* Initialise IrpSl */
	IrpSl = IoGetCurrentIrpStackLocation(Irp);
	
	/* Catch the IOCTL Code */
	CtlCode = IrpSl->Parameters.DeviceIoControl.IoControlCode;
	
	switch (CtlCode) {
		case IOCTL_HELLO:
			irp_request = 1;
			
			while(!packet_ready) {
				continue;
			}
			
			//DbgPrint("Received from the userLand: %s", pBuf);
			RtlZeroMemory(pBuf, IrpSl->Parameters.DeviceIoControl.InputBufferLength);
			//RtlCopyMemory(pBuf, sayhello, strlen(sayhello));
			RtlCopyMemory(pBuf, packet, packet_ready);
			/* finish IRP request */
			Irp->IoStatus.Status = STATUS_SUCCESS;
			Irp->IoStatus.Information = packet_ready;
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
			irp_request = 0;
			break;
		default:
			break;
	}
	
	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT theDriverObject, IN PUNICODE_STRING theRegistryPath)
{
	UINT aMediumIndex = 0;
	NDIS_STATUS aStatus, anErrorStatus;
	NDIS_MEDIUM aMediumArray = NdisMedium802_3; // specifies a ethernet network
	UNICODE_STRING anAdapterName;
	NDIS_PROTOCOL_CHARACTERISTICS aProtocolChar;
	
	NTSTATUS ret;

  UNICODE_STRING      deviceNameUnicodeString;
  UNICODE_STRING      deviceLinkUnicodeString;

	//This string must match that specified in the registery (under Services) when the protocol was installed
	NDIS_STRING aProtoName = NDIS_STRING_CONST("pf");
	
	//RtlInitUnicodeString(&deviceName, deviceNameBuffer);
	
  // We set up the name and symbolic link in Unicode
  RtlInitUnicodeString(&deviceNameUnicodeString,
                       deviceNameBuffer);
  RtlInitUnicodeString(&deviceLinkUnicodeString, 
                       deviceLinkBuffer);

	DbgPrint("Creating virtual device\n");
	
	ret = IoCreateDevice(theDriverObject, 0, &deviceNameUnicodeString, FILE_DEVICE_ROOTKIT, 0, TRUE, &g_device);
	if (NT_SUCCESS(ret)) {
    ret = IoCreateSymbolicLink(&deviceLinkUnicodeString,
                                   	&deviceNameUnicodeString);
	} else {
		char _t[255];
		_snprintf(_t, 253, "DriverEntry: ERROR IoCreateDevice failed with error 0x%08X", ret);
		DbgPrint("%s\n",_t);
		return ret;
	}
	
	DbgPrint("Loading NDIS Sniffer\n");
	
	RtlInitUnicodeString(&anAdapterName, L"\\Device\\{BDB421B0-4B37-4AA2-912B-3AA05F8A0829}");
	//RtlInitUnicodeString(&anAdapterName, L"\\Device\\{2D2E989B-6153-4787-913D-807779793B27}");
	//HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{2D2E989B-6153-4787-913D-807779793B27}
	//{449F621A-04BC-4896-BBCB-7A93708EA9B8}
	NdisInitializeEvent(&gCloseWaitEvent);
	theDriverObject->DriverUnload = OnUnload;
	
	theDriverObject->MajorFunction[IRP_MJ_CREATE] = OnOpen;
	theDriverObject->MajorFunction[IRP_MJ_CLOSE] = OnClose;
	theDriverObject->MajorFunction[IRP_MJ_READ] = OnRead;
	theDriverObject->MajorFunction[IRP_MJ_WRITE] = OnWrite;
	theDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = OnIoControl;
	
	RtlZeroMemory(&aProtocolChar, sizeof(NDIS_PROTOCOL_CHARACTERISTICS));
	
	aProtocolChar.MajorNdisVersion = 5;
	aProtocolChar.MinorNdisVersion = 0;
	aProtocolChar.Reserved = 0;
	aProtocolChar.OpenAdapterCompleteHandler = OnOpenAdapterDone;
	aProtocolChar.CloseAdapterCompleteHandler = OnCloseAdapterDone;
	aProtocolChar.SendCompleteHandler = OnSendDone;
	aProtocolChar.TransferDataCompleteHandler = OnTransferDataDone;
	aProtocolChar.ResetCompleteHandler = OnResetDone;
	aProtocolChar.RequestCompleteHandler = OnRequestDone;
	aProtocolChar.ReceiveHandler = OnReceiveStub;
	aProtocolChar.ReceiveCompleteHandler = OnReceiveDoneStub;
	aProtocolChar.StatusHandler = OnStatus;
	aProtocolChar.StatusCompleteHandler = OnStatusDone;
	aProtocolChar.Name = aProtoName;
	aProtocolChar.BindAdapterHandler = OnBindAdapter;
	aProtocolChar.UnbindAdapterHandler = OnUnBindAdapter;
	aProtocolChar.UnloadHandler = OnProtocolUnload;
	aProtocolChar.ReceivePacketHandler = OnReceivePacket;
	aProtocolChar.PnPEventHandler = OnPNPEvent;
	
	DbgPrint("Going to register Protocol");
	
	NdisRegisterProtocol(&aStatus, &gNdisProtocolHandle, &aProtocolChar, sizeof(NDIS_PROTOCOL_CHARACTERISTICS));
	
	DbgPrint("ndSniff: after NdisRegisterProtocol");
	
	if (aStatus != NDIS_STATUS_SUCCESS) {
		char _t[255];
		_snprintf(_t, 253, "DriverEntry: ERROR NdisRegisterProtocol failed with error 0x%08X", aStatus);
		DbgPrint("%s\n",_t);
		return aStatus;
	}
	
	DbgPrint("ndSniff: NdisOpenAdapter ->");
	
	NdisOpenAdapter(&aStatus, &anErrorStatus, &gAdapterHandle, &aMediumIndex, &aMediumArray, 1, gNdisProtocolHandle, &gUserStruct, &anAdapterName, 0, NULL);
	
	DbgPrint("ndSniff: NdisOpenAdapter <-");
	
	if (aStatus != NDIS_STATUS_SUCCESS) {
		if (FALSE == NT_SUCCESS(aStatus)) {
			char _t[255];
			_snprintf(_t, 253, "ndSniff: NdisOpenAdapter returned an error 0x%08X", aStatus);
			DbgPrint("%s\n", _t);
			
			if(NDIS_STATUS_ADAPTER_NOT_FOUND == aStatus) {
				DbgPrint("Adapter Not Found\n");
			}
			
			NdisDeregisterProtocol(&aStatus, gNdisProtocolHandle);
			
			if(FALSE == NT_SUCCESS(aStatus)) {
				DbgPrint("Deregister Protocol Failed\n");
			}
			
			//use for win ce according to rootkit book
			
			//NdisFreeEvent(gCloseWaitEvent);
			
			return STATUS_UNSUCCESSFUL;
		}
	} else {
		DbgPrint("ndSniff: OnOpenAdapterDone ->");
		OnOpenAdapterDone(&gUserStruct, aStatus, NDIS_STATUS_SUCCESS);
		DbgPrint("ndSniff: OnOpenAdapterDone <-");
	}
	
	DbgPrint("ndSniff: preparing buffer for packet");
	packet = ExAllocatePool(NonPagedPool, packet_size);
	if (!packet) {
		DbgPrint("ndSniff: ERROR: ENOMEM");
	}
	RtlZeroMemory(packet, packet_size);
	
	DbgPrint("ndSniff: driver entry return");
	return STATUS_SUCCESS;
}

VOID OnOpenAdapterDone(IN NDIS_HANDLE ProtocolBindingContext, IN NDIS_STATUS Status, IN NDIS_STATUS OpenErrorStatus)
{
	NDIS_STATUS aStatus;
	NDIS_REQUEST anNdisRequest;
	NDIS_STATUS anotherStatus;
	ULONG aMode = NDIS_PACKET_TYPE_ALL_LOCAL; //NDIS_PACKET_TYPE_PROMISCUOUS;
	
	DbgPrint("ndSniff: OnOpenAdapterDone called\n");
	
	if (NT_SUCCESS(OpenErrorStatus)) {
		//k card goes into aMode
		anNdisRequest.RequestType = NdisRequestSetInformation;
		anNdisRequest.DATA.SET_INFORMATION.Oid = OID_GEN_CURRENT_PACKET_FILTER;
		anNdisRequest.DATA.SET_INFORMATION.InformationBuffer = &aMode;
		anNdisRequest.DATA.SET_INFORMATION.InformationBufferLength = sizeof(ULONG);
		
		NdisRequest(&anotherStatus, gAdapterHandle, &anNdisRequest);
		
		NdisAllocatePacketPool(&aStatus, &gPacketPoolH, TRANSMIT_PACKETS, sizeof(PACKET_RESERVED));
		
		if (aStatus != NDIS_STATUS_SUCCESS) {
			return;
		}
		
		NdisAllocateBufferPool(&aStatus, &gBufferPoolH, TRANSMIT_PACKETS);
		
		if (aStatus != NDIS_STATUS_SUCCESS) {
			return;
		}
	} else {
		char _t[255];
		_snprintf(_t,253, "ndSniff: OpenAdapterDone called with error 0x%08X", OpenErrorStatus);
		DbgPrint("%s\n", _t);
	}
}

VOID OnCloseAdapterDone(IN NDIS_HANDLE ProtocolBindingContext, IN NDIS_STATUS Status)
{
	DbgPrint("ndSniff: OnClosAdapterDone called\n");
	NdisSetEvent(&gCloseWaitEvent);
}

VOID OnSendDone(IN NDIS_HANDLE ProtocolBindingContext, IN PNDIS_PACKET pPacket, IN NDIS_STATUS Status)
{
	DbgPrint("ndSniff OnSendDone called\n");
}

VOID OnTransferDataDone(IN NDIS_HANDLE thePBindingContext, IN PNDIS_PACKET thePacketp, IN NDIS_STATUS theStatus, IN UINT theBytesTransfered)
{
	PNDIS_BUFFER aNdisBufP;
	PVOID aBufferP;
	ULONG aBufferLen;
	PVOID aHeaderBufferP;
	ULONG aHeaderBufferLen;
	
	DbgPrint("ndSniff OnTransferDataDone called\n");
	
	aBufferP = RESERVED(thePacketp)->pBuffer;
	aBufferLen = theBytesTransfered;
	aHeaderBufferP = RESERVED(thePacketp)->pHeaderBufferP;
	aHeaderBufferLen = RESERVED(thePacketp)->pHeaderBufferLen;
	
	/*
	aHeaderBufferP = Ethernet Header
	aBufferP tcp/ip
	*/
	
	if (aBufferP && aHeaderBufferP) {
		ULONG aPos = 0;
		unsigned char *aPtr = NULL;
		
		aPtr = ExAllocatePool(NonPagedPool, (aHeaderBufferLen + aBufferLen));
		
		if (aPtr) {
			memcpy(aPtr, aHeaderBufferP, aHeaderBufferLen);
			memcpy(aPtr + aHeaderBufferLen, aBufferP, aBufferLen);
			
			/* woei complete packet, parse it*/
			OnSniffedPacket(aPtr, (aHeaderBufferLen + aBufferLen));
			ExFreePool(aPtr);
		}
		
		ExFreePool(aBufferP);
		ExFreePool(aHeaderBufferP);
	}
	
	NdisUnchainBufferAtFront(thePacketp, &aNdisBufP);
	
	if (aNdisBufP) {
		NdisFreeBuffer(aNdisBufP);
	}
	
	NdisReinitializePacket(thePacketp);
	NdisFreePacket(thePacketp);
	
	packet_ready = 0;
	
	return;
}

NDIS_STATUS OnReceiveStub(IN NDIS_HANDLE ProtocolBindingContext, IN NDIS_HANDLE MacReceiveContext, IN PVOID HeaderBuffer, IN UINT HeaderBufferSize, IN PVOID LookAheadBuffer, IN UINT LookaheadBufferSize, UINT PacketSize)
{
	PNDIS_PACKET pPacket;
	PNDIS_BUFFER pBuffer;
	ULONG SizeToTransfer = 0;
	NDIS_STATUS Status;
	UINT BytesTransfered;
	ULONG BufferLength;
	PPACKET_RESERVED Reserved;
	NDIS_HANDLE BufferPool;
	PVOID aTemp;
	UINT Frame_Type = 0;
	
	DbgPrint("ndSniff OnReceiveStub called\n");
	
	SizeToTransfer = PacketSize;
	
	if (HeaderBufferSize > ETHERNET_HEADER_LENGTH || (SizeToTransfer > (1514 - ETHERNET_HEADER_LENGTH))) {
		DbgPrint("OnReceiveStub: packet not accepted\n");
		return NDIS_STATUS_NOT_ACCEPTED;
	}
	
	memcpy(&Frame_Type, (((char *)HeaderBuffer) + 12), 2);
	
	if (Frame_Type != 0x0008) {
		DbgPrint("NON EthernetHeader\n");
		return NDIS_STATUS_NOT_ACCEPTED;
	}
	
	aTemp = ExAllocatePool(NonPagedPool, (1514 - ETHERNET_HEADER_LENGTH));
	
	if (aTemp) {
		RtlZeroMemory(aTemp, (1514 - ETHERNET_HEADER_LENGTH));
		NdisAllocatePacket(&Status, &pPacket, gPacketPoolH);
		
		if(NDIS_STATUS_SUCCESS == Status) {
			RESERVED(pPacket)->pHeaderBufferP = ExAllocatePool(NonPagedPool, ETHERNET_HEADER_LENGTH);
			
			if (RESERVED(pPacket)->pHeaderBufferP) {
				RtlZeroMemory(RESERVED(pPacket)->pHeaderBufferP, ETHERNET_HEADER_LENGTH);
				memcpy(RESERVED(pPacket)->pHeaderBufferP, (char *)HeaderBuffer, ETHERNET_HEADER_LENGTH);
				RESERVED(pPacket)->pHeaderBufferLen = ETHERNET_HEADER_LENGTH;
				NdisAllocateBuffer(&Status, &pBuffer, gBufferPoolH, aTemp, (1514 - ETHERNET_HEADER_LENGTH));
				
				if(NDIS_STATUS_SUCCESS == Status) {
					RESERVED(pPacket)->pBuffer = aTemp;
					
					/*this is important here we attach the buffer to the packet*/
					
					NdisChainBufferAtFront(pPacket, pBuffer);
					NdisTransferData(&(gUserStruct.mStatus), gAdapterHandle, MacReceiveContext, 0, SizeToTransfer, pPacket, &BytesTransfered);
					
					if (Status != NDIS_STATUS_PENDING) {
						/*important to call the complete routine since it's not pending*/
						OnTransferDataDone(&gUserStruct, pPacket, Status, BytesTransfered);
					}
					
					return NDIS_STATUS_SUCCESS;
				}
				
				ExFreePool(RESERVED(pPacket)->pHeaderBufferP);
				
			} else {
				DbgPrint("pHeaderBufferP allocate failed\n");
			}
			
			NdisFreePacket(pPacket);
			
		}
		
		ExFreePool(aTemp);
	}
	
	return NDIS_STATUS_SUCCESS;
}

VOID OnReceiveDoneStub(IN NDIS_HANDLE ProtocolBindingContext)
{
	DbgPrint("ndSniff OnReceiveStubDone called\n");
	return;
}

VOID OnStatus(IN NDIS_HANDLE ProtocolBindingContext, IN NDIS_STATUS Status, IN PVOID StatusBuffer, IN UINT StatusBufferSize)
{
	DbgPrint("ndSniff OnStatus called\n");
	return;
}

VOID OnStatusDone(IN NDIS_HANDLE ProtocolBindingContext)
{
	DbgPrint("ndSniff OnStatusDone called\n");
	return;
}

VOID OnResetDone(IN NDIS_HANDLE ProtocolBindingContext, IN NDIS_STATUS Status)
{
	DbgPrint("ndSniff OnResetDone called\n");
	return;
}

VOID OnRequestDone(IN NDIS_HANDLE ProtocolBindingContext, IN PNDIS_REQUEST NdisRequest, IN NDIS_STATUS Status)
{
	DbgPrint("ndSniff OnRequestDone called\n");
	return;
}

VOID OnBindAdapter(OUT PNDIS_STATUS theStatus, IN NDIS_HANDLE theBindContext, IN PNDIS_STRING theDeviceNameP, IN PVOID theSS1, IN PVOID theSS2)
{
	DbgPrint("ndSniff OnBindAdapter called\n");
	return;
}

VOID OnUnBindAdapter(OUT PNDIS_STATUS theStatus, IN NDIS_HANDLE theBindContext, IN PNDIS_HANDLE theUnbindContext)
{
	DbgPrint("ndSniff OnUnBindAdapter called\n");
	return;
}

NDIS_STATUS OnPNPEvent(IN NDIS_HANDLE ProtocolBindingContext, IN PNET_PNP_EVENT pNetPnPEvent)
{
	DbgPrint("ndSniff OnPNPEvent called\n");
	return NDIS_STATUS_SUCCESS;
}

VOID OnProtocolUnload(VOID)
{
	DbgPrint("ndSniff OnProtocolUnload called\n");
	return;
}

INT OnReceivePacket(IN NDIS_HANDLE ProtocolBindingContext, IN PNDIS_PACKET Packet)
{
	DbgPrint("ndSniff OnReceivePacket called\n");
	return 0;
}

VOID OnUnload(IN PDRIVER_OBJECT DriverObject)
{
	NTSTATUS ret;
	NDIS_STATUS Status;
  UNICODE_STRING      deviceNameUnicodeString;
  UNICODE_STRING      deviceLinkUnicodeString;

	DbgPrint("ndSniff: OnUnload called\n");
	NdisResetEvent(&gCloseWaitEvent);
	
	NdisCloseAdapter(&Status, gAdapterHandle);
	
	if (Status == NDIS_STATUS_PENDING) {
		DbgPrint("NDIS BUSY\n");
		NdisWaitEvent(&gCloseWaitEvent, 0);
	}
	
	NdisDeregisterProtocol(&Status, gNdisProtocolHandle);
	
	if (FALSE == NT_SUCCESS(Status)) {
		DbgPrint("Deregister failed\n");
	}
	
	DbgPrint("NdisDeregisterProtocol done\n");
	
	DbgPrint("Deleting virtual device\n");
	//ret = IoDeleteDevice(&g_device);
	//IoDeleteDevice(DriverObject->DeviceObject);
	/*
	if (ret != STATUS_SUCCESS) {
		char _t[255];
		_snprintf(_t, 253, "DriverEntry: ERROR IoDeleteDevice failed with error 0x%08X", ret);
		DbgPrint("%s\n",_t);
	}
	*/

  
  RtlInitUnicodeString(&deviceNameUnicodeString,
                       deviceNameBuffer);
  RtlInitUnicodeString(&deviceLinkUnicodeString, 
                       deviceLinkBuffer);
  
  IoDeleteSymbolicLink(&deviceNameUnicodeString);
  IoDeleteDevice(DriverObject->DeviceObject);
}

/*
From here on we analyze the packets
*/
VOID OnSniffedPacket(const unsigned char* theData, int theLen)
{
	int i;
	int l;
	PACKET_TCP rPacketT;
	PACKET_UDP rPacketU;
	PACKET_ICMP rPacketI;
	
	IP_HDR *ip = (IP_HDR *) ((unsigned char *) theData + sizeof(ETH_HDR));
	DbgPrint("PROTOBEFORE:: %i %d 0x%x\n", ip->proto, ip->proto, ip->proto);
	
	DbgPrint("PACKDUMP --->:\n");
	l = 0;
	for (l = 0; l < theLen; l++){
		DbgPrint(" %0.2X ", (unsigned char *) theData[l]);
	}
	DbgPrint("\nPACKDUMP <---:\n");
	
	packet_ready = 0;
	RtlZeroMemory(packet, packet_size);
	memcpy(packet, theData, theLen);
	// packet_size = theLen;
	packet_ready = theLen;
	
	#if 0
	if (IPPROTO_TCP == ip->proto) {
		int i;
		rPacketT.ethHdr = (ETH_HDR *) theData;
		rPacketT.ipHdr = (IP_HDR *) (theData + sizeof(ETH_HDR));
		rPacketT.tcpHdr = (TCP_HDR *) (theData + (sizeof(ETH_HDR) + sizeof(IP_HDR)));
		rPacketT.data = (unsigned char *) (theData + sizeof(ETH_HDR) + sizeof(IP_HDR) + sizeof(TCP_HDR));
		rPacketT.dataLen = (theLen - (sizeof(ETH_HDR) + sizeof(IP_HDR) + sizeof(TCP_HDR)));
		
		DbgPrint("TCP\n");
		
		if (findStr(rPacketT.data, "hacker")) {
			DbgPrint("TRUE\n");
		} else {
			DbgPrint("FALSE\n");
		}
		
		return;
		
	} else if (IPPROTO_UDP == ip->proto) {
		int i;
		rPacketU.ethHdr = (ETH_HDR *) theData;
		rPacketU.ipHdr = (IP_HDR *) (theData + sizeof(ETH_HDR));
		rPacketU.udpHdr = (UDP_HDR *) (theData + (sizeof(ETH_HDR) + sizeof(IP_HDR)));
		rPacketU.data = (unsigned char *) (theData + sizeof(ETH_HDR) + sizeof(IP_HDR) + sizeof(UDP_HDR));
		rPacketU.dataLen = (theLen - (sizeof(ETH_HDR) + sizeof(IP_HDR) + sizeof(UDP_HDR)));
		
		DbgPrint("UDP\n");
		if (findStr(rPacketT.data, "hacker")) {
			DbgPrint("TRUE\n");
		} else {
			DbgPrint("FALSE\n");
		}
		
		return;
		
	} else if (IPPROTO_ICMP == ip->proto) {
		int i;
		rPacketI.ethHdr = (ETH_HDR *) theData;
		rPacketI.ipHdr = (IP_HDR *) (theData + sizeof(ETH_HDR));
		rPacketI.icmpHdr = (ICMP_HDR *) (theData + (sizeof(ETH_HDR) + sizeof(IP_HDR)));
		rPacketI.data = (unsigned char *) (theData + sizeof(ETH_HDR) + sizeof(IP_HDR) + sizeof(ICMP_HDR));
		rPacketI.dataLen = (theLen - (sizeof(ETH_HDR) + sizeof(IP_HDR) + sizeof(ICMP_HDR)));
		
		DbgPrint("ICMP\n");
		
		if (findStr(rPacketI.data, "ZXX")) {
			DbgPrint("TRUE\n");
		} else {
			DbgPrint("FALSE\n");
		}
		
		return;
		
	} else {
		/*
		you can implement the rest of the protocols yourself.
		*/
		DbgPrint("UNDEFINED\n");
	}
	#endif
	return;
}

/*thx to BackBon3 spared me the fiddling around*/
BOOLEAN findStr(const char *psz,const char *tofind)
{
	const char *ptr = psz;
	const char *ptr2;
	
	while (1) {
		ptr = strchr(psz, toupper(*tofind));
		ptr2 = strchr(psz, tolower(*tofind));
		
		if (!ptr) {
			ptr = ptr2; /* was ptr2 = ptr.  Big bug fixed 10/22/99 */
		}
		if (!ptr) {
			break;
		}
		
		if (ptr2 && (ptr2 < ptr)) {
			ptr = ptr2;
		}
		
		if (!_strnicmp(ptr, tofind, strlen(tofind))) {
			return TRUE;
		}
		
		psz = ptr + 1;
	}
	
	return FALSE;
} /* stristr */

/* TODO: AUTOGET ADAPTERNAME
HKLM\SYSTEM\CurrentControlSet\Service\Tcpip\Parame  ters\Interfaces\{number}

PWCHAR GetAdapterName()
{
PWCHAR AdapterName;
NTSTATUS ntStatus;
PHANDLE oHandle;

ntStatus = ZwOpenKey(&oHandle,FILE_READ_DATA,

}*/

#elif ( defined(SYS_NT) )

/* --------------------  library space routine  ------------------- */

#pragma message("SYS_NT: library space")

#include "../connect.h"

int cnct_filter_bpf(char *iface, socket_t rs)
{
	/* fallback mode for USR engine on NT */
	
	LOG_IN;
	
	/* TODO: implementation: dump goes here */
	
	LOG_OUT;
	
	return 0;
}

socket_t cnct_packet_recv_init(int engine, char *iface, int proto, char *rule)
{
	LOG_IN;
	
	/* TODO: implementation: init of device goes here */
	
	LOG_OUT;
	
	return CNCT_INVALID;
}

ssize_t cnct_packet_recv (socket_t sd, unsigned char *packet, size_t len)
{
	LOG_IN;
	
	/* TODO: implementation: ioctl for device to get packet goes here */
	
	LOG_OUT;
	
	return 0;
}

#else

/* --------------------  user space routine  ------------------- */

#pragma message("SYS_NT: user space")

#include <stdio.h>
#include <windows.h>
#include <winioctl.h>
#include <stdlib.h>
#include <string.h>

#define SIOCTL_TYPE 40000
#define IOCTL_HELLO CTL_CODE(SIOCTL_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define STR_DEV_LEN 46*2

/*
 * TODO:
 * - functions' name refactoring (e.g., init_ndis_device -> iface_open/iface_close)
 * - merging code with connect/ tree, integrating into build process
 * - generate full device string in kernel space
 * - fixing FILE_DEVICE_, adding DIRECT_IO in device extension
 * - extending ioctl's (_recv,_send,_open,_close,_file,...)
 * - adding autodetect of ifaces in user space
 * - adding file support in user/kernel space
 * - scripts for autobuild(nmake)/autosign(see msdn)
 */

struct user_irp {
	int irp_type;
	wchar_t irp_data[STR_DEV_LEN];
};

int __cdecl main(int argc, char* argv[])
{
	HANDLE hDevice;
	DWORD NombreByte;
	int i;
	unsigned char out[64*1024];
	struct user_irp uirp;
	char *sayhello = "Hi! From UserLand";
	
	uirp.irp_type = 1;
	memcpy(uirp.irp_data, L"\\Device\\{BDB421B0-4B37-4AA2-912B-3AA05F8A0829}", STR_DEV_LEN);
	// Fills the array 'out' by zeros
	ZeroMemory(out, sizeof(out));
	
	// Opens our Device
	hDevice = CreateFile("\\\\.\\myDevice1", GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	printf("Handle pointer: %p\n", hDevice);
	
	// We send a CTL command to read our message in kernel
	/*
	DeviceIoControl(hDevice, IOCTL_HELLO, sayhello, strlen(sayhello), out, sizeof(out), &NombreByte, NULL);
	
	printf("[len=%d]", NombreByte);
	for (i = 0; i < 20; i++) {
		printf(" %02X", out[i]);
	}
	printf("\n");
	*/
	DeviceIoControl(hDevice, IOCTL_HELLO, &uirp, sizeof(struct user_irp), out, sizeof(out), &NombreByte, NULL);

	CloseHandle(hDevice); // Close the handle: We should observe the function CloseFunction is called
	return 0;
}

#endif

