/*
Kernel space sniffer.
Guidelines used: Rootkits, subverting the windows kernel
 NT Rootkit
Made by: DiabloHorn
Purpose: Sniff data and filter it on text.
Thanks to: n0limit,BackBon3
*/

/*
This is the part for the sniffer.
*/

#define ETHERNET_HEADER_LENGTH     14
#define RESERVED(_p)              ((PPACKET_RESERVED)((_p)->ProtocolReserved))
#define TRANSMIT_PACKETS          128

typedef struct _PACKET_RESERVED {
	LIST_ENTRY  ListElement;
	PIRP        Irp;
	PVOID       pBuffer; /* used for buffers built in kernel mode */
	ULONG       bufferLen;
	PVOID       pHeaderBufferP;
	ULONG       pHeaderBufferLen;
	PMDL        pMdl;
} PACKET_RESERVED, *PPACKET_RESERVED;

struct UserStruct {
	ULONG        mData;
	NDIS_STATUS  mStatus;
} gUserStruct;

NDIS_HANDLE  gAdapterHandle;
NDIS_HANDLE  gNdisProtocolHandle;
NDIS_EVENT   gCloseWaitEvent;
NDIS_HANDLE  gPacketPoolH;
NDIS_HANDLE  gBufferPoolH;

VOID         OnOpenAdapterDone   (IN NDIS_HANDLE ProtocolBindingContext, IN NDIS_STATUS  Status, IN NDIS_STATUS OpenErrorStatus);
VOID         OnCloseAdapterDone  (IN NDIS_HANDLE ProtocolBindingContext, IN NDIS_STATUS  Status);
VOID         OnSendDone          (IN NDIS_HANDLE ProtocolBindingContext, IN PNDIS_PACKET pPacket, IN NDIS_STATUS Status);
VOID         OnTransferDataDone  (IN NDIS_HANDLE thePBindingContext,     IN PNDIS_PACKET thePacketp, IN NDIS_STATUS theStatus, IN UINT theBytesTransfered);
NDIS_STATUS  OnReceiveStub       (IN NDIS_HANDLE ProtocolBindingContext, IN NDIS_HANDLE MacReceiveContext, IN PVOID HeaderBuffer, IN UINT HeaderBufferSize, IN PVOID LookAheadBuffer, IN UINT LookaheadBufferSize, UINT PacketSize);
VOID         OnReceiveDoneStub   (IN NDIS_HANDLE ProtocolBindingContext);
VOID         OnStatus            (IN NDIS_HANDLE ProtocolBindingContext, IN NDIS_STATUS Status, IN PVOID StatusBuffer, IN UINT StatusBufferSize);
VOID         OnStatusDone        (IN NDIS_HANDLE ProtocolBindingContext);
VOID         OnResetDone         (IN NDIS_HANDLE ProtocolBindingContext, IN NDIS_STATUS Status);
VOID         OnRequestDone       (IN NDIS_HANDLE ProtocolBindingContext, IN PNDIS_REQUEST NdisRequest, IN NDIS_STATUS Status);
VOID         OnBindAdapter       (OUT PNDIS_STATUS theStatus,            IN NDIS_HANDLE theBindContext, IN PNDIS_STRING theDeviceNameP, IN PVOID theSS1, IN PVOID theSS2);
VOID         OnUnBindAdapter     (OUT PNDIS_STATUS theStatus,            IN NDIS_HANDLE theBindContext, IN PNDIS_HANDLE theUnbindContext);
NDIS_STATUS  OnPNPEvent          (IN NDIS_HANDLE ProtocolBindingContext, IN PNET_PNP_EVENT pNetPnPEvent);
VOID         OnProtocolUnload    (VOID);
INT          OnReceivePacket     (IN NDIS_HANDLE ProtocolBindingContext, IN PNDIS_PACKET Packet);
VOID         OnUnload            (IN PDRIVER_OBJECT DriverObject);

/*
From now on it's the packet analyzer
*/

/*These are the protocols sniffed add yours to sniff more*/

#define IPPROTO_ICMP    1              /* control message protocol */
#define IPPROTO_TCP     6              /* tcp */
#define IPPROTO_UDP    17              /* user datagram protocol */

/*structs to parse only the headers of the received raw packet*/
typedef struct ether_header {
	unsigned char   h_dest[6];    /* destination eth addr*/
	unsigned char   h_source[6];  /* source ether addr*/
	unsigned short  h_proto;      /* packet type ID field*/
} ETH_HDR;

typedef struct _iphdr {
	unsigned char   h_lenver;
	unsigned char   tos;
	unsigned short  total_len;
	unsigned short  ident;
	unsigned short  frag_and_flags;
	unsigned char   ttl;
	unsigned char   proto;
	unsigned short  checksum;
	unsigned int    sourceIP;
	unsigned int    destIP;
} IP_HDR;

typedef struct tcphdr {
	unsigned short int  sport;
	unsigned short int  dport;
	unsigned int        th_seq;
	unsigned int        th_ack;
	unsigned char       th_x2:4;
	unsigned char       th_off:4;
	unsigned char       Flags;
	unsigned short int  th_win;
	unsigned short int  th_sum;
	unsigned short int  th_urp;
	// unsigned char *data;
} TCP_HDR;

typedef struct udphdr {
	unsigned  shortsport;
	unsigned  shortdport;
	unsigned  shortlength;
	unsigned  shortchecksum;
} UDP_HDR;

typedef struct icmphdr {
	unsigned char   icmp_type;
	unsigned char   icmp_code;
	unsigned short  icmp_cksum;
	unsigned short  icmp_id;
	unsigned short  icmp_seq;
	//8bytes
} ICMP_HDR;

/*Used to parse the complete received raw packet*/
typedef struct _rawPacketTCP {
	ETH_HDR       *ethHdr;
	IP_HDR        *ipHdr;
	TCP_HDR       *tcpHdr;
	unsigned char *data;
	int            dataLen;
} PACKET_TCP, *PPACKET_TCP;

typedef struct _rawPacketUDP {
	ETH_HDR       *ethHdr;
	IP_HDR        *ipHdr;
	UDP_HDR       *udpHdr;
	unsigned char *data;
	int            dataLen;
} PACKET_UDP, *PPACKET_UDP;

typedef struct _rawPacketICMP {
	ETH_HDR       *ethHdr;
	IP_HDR        *ipHdr;
	ICMP_HDR      *icmpHdr;
	unsigned char *data;
	int            dataLen;
} PACKET_ICMP,*PPACKET_ICMP;

VOID    OnSniffedPacket  (const unsigned char* theData,         int theLen);
BOOLEAN findStr          (const char *psz,     const char *tofind);

