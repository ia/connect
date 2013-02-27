
/*** *** *** pragmas *** *** ***/

#pragma message("SYS_NT: kernel space")
#pragma warning(disable:4700)

/*** *** *** defines *** *** ***/

/* versioning */
#define  NDIS50            1
#define  PROTO_NDIS_MAJOR  5
#define  PROTO_NDIS_MINOR  0
/* TODO: use define minor/major */

/* includes */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <malloc.h>
#include <errno.h>
#include <sys/types.h>

#include <wdm.h>
#include <ntddk.h>
#include <ndis.h>

/* custom global routine */
#define  ETH_HLEN          14
#define  ETH_ALEN           6         /* Octets in one ethernet addr	 */
#define  ETHER_ADDR_LEN    ETH_ALEN   /* Size of ethernet addr */

#ifndef __func__
#	define __func__ __FUNCTION__      /* stupid MS monkeys cannot into standart defines */
#endif

/* TODO: rename two */
#define  RESERVED(_p)           ((PPACKET_RESERVED)((_p)->ProtocolReserved))
#define  RSRVD_PCKT_CTX(_p)     ((struct packet_ctx *)((_p)->ProtocolReserved))
#define  TRANSMIT_PACKETS       128
#define  MTU                    1514

/* ioctl related defines */
#define  SIOCTL_TYPE            40000
#define  IOCTL_HELLO CTL_CODE   (SIOCTL_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define  FILE_DEVICE_ROOTKIT    0x00002a7b

/* proto related constants */
#define  IPPROTO_ICMP       1   /* control message protocol */
#define  IPPROTO_TCP        6   /* tcp */
#define  IPPROTO_UDP       17   /* user datagram protocol */

/* values */
#define  NT_OK                 STATUS_SUCCESS
#define  NT_ERR                STATUS_UNSUCCESSFUL
#define  ND_OK                 NDIS_STATUS_SUCCESS
#define  IS_ND_OK(   r)        (r == NDIS_STATUS_SUCCESS)
#define  IS_NT_OK(   r)        NT_SUCCESS(r)
#define  IS_NT_ERR(  r)        NT_ERROR  (r)  /* http://msdn.microsoft.com/en-us/library/windows/hardware/ff565436%28v=vs.85%29.aspx */
#define  IRP_ASBUF(  i)        (i->AssociatedIrp.SystemBuffer)
#define  IRP_IBLEN(  s)        (s->Parameters.DeviceIoControl.InputBufferLength)
#define  IRP_IOCTL(  s)        (s->Parameters.DeviceIoControl.IoControlCode)
#define  IRP_DONE(  rp, info, ret) \
		rp->IoStatus.Status = ret; rp->IoStatus.Information = info; IoCompleteRequest(rp, IO_NO_INCREMENT);
/* functions */
	/* basic */
#define    memzero(            src, len)    memset(                       src,     '\0',len            )
#define nt_malloc(             len     )    ExAllocatePool(               NonPagedPool, len            )
#define nt_free(               src     )    ExFreePool(                            src                 )
#define nt_memzero(            src, len)    RtlZeroMemory(                         src, len            )
#define nt_memcpy(        dst, src, len)    RtlCopyMemory(                dst,     src, len            )
#define nt_init_ustring(  dst, src     )    RtlInitUnicodeString(         dst,     src                 )
#define nt_creat_link(    dst, src     )    IoCreateSymbolicLink(         dst,     src                 )
#define nt_irp_complete(       ir      )    IoCompleteRequest(                     ir, IO_NO_INCREMENT )
#define nt_irp_get_stack(      ir      )    IoGetCurrentIrpStackLocation(          ir                  )
#define nt_unlink_link(        str     )    IoDeleteSymbolicLink(                  str                 )
#define nt_unlink_dev(         dev     )    IoDeleteDevice(                        dev                 )
	/* complex */
#define nt_creat(mod, name, dev) \
	IoCreateDevice(mod, 0, name, FILE_DEVICE_ROOTKIT, FILE_DEVICE_SECURE_OPEN, false, dev)

/* routine */
#define  PROTONAME  "pf"
#define LPROTONAME  "pf"
#define  MODNAME    "pf"
#define LMODNAME    "pf"

#ifndef RELEASE
#	define printk(  fmt, ...   )    DbgPrint(fmt ##__VA_ARGS__)
#	define printm(  msg        )    DbgPrint("%s: %s: %d: %s\n"   ,                       MODNAME, __func__, __LINE__, msg      )
#	define printl                   DbgPrint("%s: %s: %d: "       ,                       MODNAME, __func__, __LINE__           )
#	define printmd( msg, d     )    DbgPrint("%s: %s: %d: %s: %d (0x%08X)\n",             MODNAME, __func__, __LINE__, msg, d, d)
#	define DBG_IN                   DbgPrint("%s: == >> %s: %d\n" ,                       MODNAME, __func__, __LINE__           )
#	define DBG_OUT                  DbgPrint("%s: << == %s: %d\n" ,                       MODNAME, __func__, __LINE__           )
#	define DBG_OUT_V                DbgPrint("%s: << == %s: %d\n" ,                       MODNAME, __func__, __LINE__           ); return
#	define DBG_OUT_VM(    m    )    DbgPrint("%s: << == %s: %d: %s\n" ,                   MODNAME, __func__, __LINE__, m        ); return

/* new */
/* return */
#	define DBG_OUT_R(       r  )    DbgPrint("%s: << == %s: %d\n" ,                       MODNAME, __func__, __LINE__           ); return r
/* Return value + Print value */
#	define DBG_OUT_RP(      r  )    DbgPrint("%s: << == %s: %d: ret = %d (0x%08X)\n",     MODNAME, __func__, __LINE__, r  , r   ); return r
/* return Void, but Print returned value from the previous call */
#	define DBG_OUT_VP(      r  )    DbgPrint("%s: << == %s: %d: ret = %d (0x%08X)\n",     MODNAME, __func__, __LINE__, r  , r   ); return
/* Return value, Print returned value and additional Message with information */
#	define DBG_OUT_RPM(  m, r  )    DbgPrint("%s: << == %s: %d: %s: ret = %d (0x%08X)\n", MODNAME, __func__, __LINE__, m  , r, r); return r
/* return Void, Print returned value and additional Message with information */
#	define DBG_OUT_VPM(  m, r  )    DbgPrint("%s: << == %s: %d: %s: ret = %d (0x%08X)\n", MODNAME, __func__, __LINE__, m  , r, r); return

/* old */
//#	define DBG_OUT_RET(     r   )  DbgPrint("%s: << == %s: %d\n" ,                       MODNAME, __func__, __LINE__           ); return r
//#	define DBG_OUT_RET_P(   r   )  DbgPrint("%s: << == %s: %d: ret = %d (0x%08X)\n",     MODNAME, __func__, __LINE__, r  , r   ); return r
//#	define DBG_OUT_RET_PV(  r   )  DbgPrint("%s: << == %s: %d: ret = %d (0x%08X)\n",     MODNAME, __func__, __LINE__, r  , r   ); return
//#	define DBG_OUT_RET_PM(  m, r)  DbgPrint("%s: << == %s: %d: %s: ret = %d (0x%08X)\n", MODNAME, __func__, __LINE__, m  , r, r); return r
//#	define DBG_OUT_RET_PMV( m, r)  DbgPrint("%s: << == %s: %d: %s: ret = %d (0x%08X)\n", MODNAME, __func__, __LINE__, m  , r, r); return

#	define printdbg(fmt, ...   )    printl; DbgPrint(fmt ##__VA_ARGS__)

/*
#else
#	define printk(   fmt, ... )
#	define printm(   msg      )
#	define printmd(  msg, d   )
#	define printdbg( msg, d   )
#	define DBG_IN
#	define DBG_OUT
#	define DBG_OUT_V              return
#	define DBG_OUT_R(   r   )    return r
#	define DBG_OUT_RET_RP( r   )    return r
#	define DBG_OUT_RET_M( m, r)    return r
#	define DBG_OUT_RET_V( m, r)    return
*/

#endif

/* new */
#define  RET_ON_ERRND_VPM( m, r    )    if (!(IS_ND_OK(r)))   { DBG_OUT_VPM(m, r);           }
#define  RET_ON_ERRND_RPM( m, r    )    if (!(IS_ND_OK(r)))   { DBG_OUT_RPM(m, r);           }
#define  RET_ON_ERRND_VP(     r    )    if (!(IS_ND_OK(r)))   { DBG_OUT_VP(r);               }
#define  RET_ON_ERRNT_VP(     r    )    if (!(NT_SUCCESS(r))) { DBG_OUT_VP(r);               }
#define  RET_ON_ERRNT_RP(     r    )    if (!(NT_SUCCESS(r))) { DBG_OUT_RP(r);               }
#define  RET_ON_V_RP(         r, v )    if (r != v)           { DBG_OUT_RP(r);               }
#define  RET_ON_V_RPM(  v, m, r    )    if (v)                { DBG_OUT_RPM(m, r);           }
#define  RET_ON_V_VPM(  v, m, r    )    if (v)                { DBG_OUT_VPM(m, r);           }

/* old */
/*
#define  RET_ON_ERR_MV_ND( m, r   )     if (!(IS_ND_OK(r)))   { DBG_OUT_VPM(m, r);           }
#define  RET_ON_ERR_M_ND(  m, r   )     if (!(IS_ND_OK(r)))   { DBG_OUT_RPM(m, r);            }
#define  RET_ON_ERR_V_ND(  r      )     if (!(IS_ND_OK(r)))   { DBG_OUT_VP(r);               }
#define  RET_ON_ERR_V(     r      )     if (!(NT_SUCCESS(r))) { DBG_OUT_VP(r);               }
#define  RET_ON_ERR(       r      )     if (!(NT_SUCCESS(r))) { DBG_OUT_RP(r);                }
#define  RET_ON_VAL(       r, v   )     if (r != v)           { DBG_OUT_RP(r);                }
#define  RET_ON_VAL_MR(    v, m, r)     if (v)                { DBG_OUT_RPM(m, r);            }
#define  RET_ON_VAL_MRV(   v, m, r)     if (v)                { DBG_OUT_VPM(m, r);           }
*/

#define  RET_ON_NULL(      ptr     )    if (!ptr)             { printm("ENOMEM"); return NT_ERR; }


#define IRP_IFACE 1
#define IFACE_LEN 38

/*** *** *** data types *** *** ***/


/*** custom types ***/


/* defining standart C types */


#ifndef true
#define true  TRUE
#endif
#ifndef false
#define false FALSE
#endif


typedef signed char     int8_t;
typedef signed short    int16_t;
typedef signed int      int32_t;
typedef unsigned char   uint8_t;
typedef unsigned short  uint16_t;
typedef unsigned int    uint32_t;

typedef unsigned char   u_char;
typedef unsigned short  u_short;
typedef unsigned int    u_int;
typedef unsigned long   u_long;

typedef unsigned char   uchar;
typedef unsigned short  ushort;
typedef unsigned int    uint;
typedef unsigned long   ulong;


/* redefining existing nt types */


	/* simple */
typedef  NTSTATUS                       nt_ret;
typedef  NDIS_STATUS                    nd_ret;
	/* complex */
typedef  NET_PNP_EVENT                  nd_pnp_ev;
typedef  UNICODE_STRING                 ustring;
typedef  LARGE_INTEGER                  lrgint;
typedef  DRIVER_OBJECT                  mod_obj;   /* PDRIVER_OBJECT       *mod_obj   */
typedef  DEVICE_OBJECT                  dev_obj;   /* PDEVICE_OBJECT       *dev_obj   */
typedef  MDL                            mdl;       /* PMDL                 *mdl       */
typedef  IRP                            irp;       /* PIRP                 *irp       */
typedef  IO_STACK_LOCATION              io_stack;  /* PIO_STACK_LOCATION   *io_stack  */
typedef  NDIS_STRING                    nd_str;
typedef  NDIS_PACKET                    nd_pack;
typedef  NDIS_BUFFER                    nd_buf;
typedef  NDIS_HANDLE                    nd_hndl;
typedef  NDIS_EVENT                     nd_ev;
typedef  NDIS_REQUEST                   nd_req;
typedef  NDIS_MEDIUM                    nd_medm;
typedef  NDIS_PROTOCOL_CHARACTERISTICS  nd_proto;
typedef  LIST_ENTRY                     lent;
typedef  KSPIN_LOCK                     spin_lock;
typedef  KIRQL                          irq;
typedef  NDIS_PHYSICAL_ADDRESS          nd_phyaddr;

/*** custom structs ***/


struct timeval {
        long    tv_sec;         ///< seconds
        long    tv_usec;        ///< microseconds
};


/* This is a name for the 48 bit ethernet address available on many systems. */
struct ether_addr {
	uint8_t  ether_addr_octet[ETH_ALEN];
}; /*__attribute__ ((__packed__))*/


/* 10Mb/s ethernet header */
struct ether_header {
	uint8_t  ether_dhost[ETH_ALEN];  /* destination eth addr */
	uint8_t  ether_shost[ETH_ALEN];  /* source ether addr    */
	uint16_t ether_type;             /* packet type ID field */
} /*__attribute__ ((__packed__))*/;

struct in_addr {
    unsigned long s_addr;          // load with inet_pton()
};

struct ip {
//#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int   ip_hl:4;  /* header length */
	unsigned int   ip_v:4;   /* version */
//#endif
/*
#if __BYTE_ORDER == __BIG_ENDIAN
	unsigned int ip_v:4;
	unsigned int ip_hl:4;
#endif
*/
	uint8_t        ip_tos;   /* type of service */
	u_short        ip_len;   /* total length */
	u_short        ip_id;    /* identification */
	u_short        ip_off;   /* fragment offset field */
#define IP_RF          0x8000    /* reserved fragment flag */
#define IP_DF          0x4000    /* dont fragment flag */
#define IP_MF          0x2000    /* more fragments flag */
#define IP_OFFMASK     0x1fff    /* mask for fragmenting bits */
	uint8_t        ip_ttl;   /* time to live */
	uint8_t        ip_p;     /* protocol */
	u_short        ip_sum;   /* checksum */
	struct in_addr ip_src;   /* source address */
	struct in_addr ip_dst;   /* dest address */
};


typedef struct _PACKET_RESERVED {
	LIST_ENTRY  ListElement;
	PIRP        Irp;
	PVOID       pBuffer; /* used for buffers built in kernel mode */
	ULONG       bufferLen;
	PVOID       pHeaderBufferP;
	ULONG       pHeaderBufferLen;
	PMDL        pMdl;
} PACKET_RESERVED, *PPACKET_RESERVED;


struct packet_ctx {
	lent        entry;
	irp        *rp;
	void       *pbuf;
	ulong       pbuf_len;
	void       *phdr_buf;
	ulong       phdr_buf_len;
	mdl        *m;
};


struct user_ctx {
	ulong          data;
	nd_ret         status;
};


struct module_ctx {
	dev_obj       *device;
	const wchar_t  device_path;
	const wchar_t  device_link;
	nd_hndl        iface_hndl;
	nd_hndl        proto_hndl;
	uchar         *packet;
	size_t         packet_size;
	int            packet_ready;
	nd_hndl        packet_pool;
	nd_hndl        buffer_pool;
	nd_ev          closew_event;
};

#define STR_DEV_LEN 46*2
struct user_irp {
	int irp_type;
	wchar_t irp_data[STR_DEV_LEN];
};

/*** *** *** declarations of functions *** *** ***/


int      gettimeofday       (struct timeval *dst);

void     ndis_packet_recv   (const uchar *packet, int len);
void     ndis_packet_send   (const uchar *packet, int len);

void     ndis_status        (nd_hndl protobind_ctx  , nd_ret      s        , void    *sbuf, uint sbuf_len);
void     ndis_status_cmplt  (nd_hndl protobind_ctx);
void     ndis_iface_open    (nd_hndl protobind_ctx  , nd_ret      s        , nd_ret   err);
void     ndis_iface_bind    (nd_ret *s              , nd_hndl     bind_ctx , nd_str  *devname, void *ss1, void *ss2);
void     ndis_iface_unbind  (nd_ret *s              , nd_hndl     bind_ctx , nd_hndl *unbind_ctx);
void     ndis_iface_close   (nd_hndl protobind_ctx  , nd_ret      s);
void     ndis_reset         (nd_hndl protobind_ctx  , nd_ret      s);
void     ndis_send          (nd_hndl protobind_ctx  , nd_pack    *npacket  , nd_ret   s);
nt_ret   ndis_recv          (nd_hndl protobind_ctx  , nd_hndl     mac_ctx  , void    *hdr_buf, uint hdr_buf_len, void *labuf, uint labuf_len, uint psize);
void     ndis_recv_pckt     (nd_hndl protobind_ctx  , nd_pack    *npacket);
void     ndis_recv_cmplt    (nd_hndl protobind_ctx);
void     ndis_transfer      (nd_hndl protobind_ctx  , nd_pack    *tx_packet, nd_ret   ret, uint tx);
void     ndis_request       (nd_hndl protobind_ctx  , nd_req     *nreq     , nd_ret   s);
void     ndis_pnp           (nd_hndl protobind_ctx  , nd_pnp_ev  *pev);
void     ndis_unload        (void);

nt_ret   dev_open     (dev_obj *dobj, irp *i)           ;
nt_ret   dev_read     (dev_obj *dobj, irp *i)           ;
nt_ret   dev_write    (dev_obj *dobj, irp *i)           ;
nt_ret   dev_ioctl    (dev_obj *dobj, irp *i)           ;
nt_ret   dev_close    (dev_obj *dobj, irp *i)           ;

void     iface_open   (wchar_t *iface, int iface_len)   ;
void     iface_close  (wchar_t *iface, int iface_len)   ;

nt_ret   init_ndis    (mod_obj *mobj)                   ;
nt_ret   init_device  (mod_obj *mobj)                   ;
nt_ret   init_ctx     (void)                            ;
void     exit_ndis    (mod_obj *mobj)                   ;
void     exit_device  (mod_obj *mobj)                   ;
void     exit_module  (mod_obj *mobj)                   ;
nt_ret   init_module  (mod_obj *mobj)                   ;
//nt_ret   DriverEntry  (mod_obj *mobj, ustring *regpath) ;


/*** *** *** global variables *** *** ***/

nd_str             g_dev_prefix = NDIS_STRING_CONST("\\Device\\");

dev_obj           *g_device;
const wchar_t      g_devpath[] = L"\\Device\\myDevice1";     // Define the device
const wchar_t      g_devlink[] = L"\\DosDevices\\myDevice1"; // Symlink for the device
nd_hndl            g_iface_hndl[8];
int                g_iface_indx = 0;
nd_hndl            g_proto_hndl;
nd_hndl            g_buffer_pool;
nd_hndl            g_packet_pool;
uchar             *g_packet       = NULL     ;
size_t             g_packet_size  = 64 * 1024;
int                g_packet_ready = 0;
nd_ev              g_closew_event;
int                g_iface_ready  = 0;
ustring            g_iface_name;

struct user_ctx    g_usrctx;
struct module_ctx  g_modctx;
struct packet_ctx  g_pckctx;

spin_lock          g_splock;
irq                g_irq;
nd_phyaddr         g_phymax = NDIS_PHYSICAL_ADDRESS_CONST(-1,-1);


/*** *** *** helper functions *** *** ***/


int gettimeofday(struct timeval *dst)
{
	lrgint system_time;
	lrgint local_time;
	
	KeQuerySystemTime(&system_time);
	ExSystemTimeToLocalTime(&system_time, &local_time);
	
	dst->tv_sec  = (long) (local_time.QuadPart / 10000000 - 11644473600);
	dst->tv_usec = (long)((local_time.QuadPart % 10000000) / 10);
	
	return 0;
}


/*** *** *** mainline functions *** *** ***/


void ndis_packet_recv(const uchar *packet, int len)
{
	struct ip *iph = (struct ip *) (packet + sizeof(struct ether_header));
	
	DBG_IN;
	//printmd("proto:", iph->ip_p);
	
	g_packet_ready = 0;
	nt_memzero(g_packet, g_packet_size);
	memcpy(g_packet, packet, len);
	g_packet_ready = len;
	
	if (len == MTU) {
		uchar *zero = nt_malloc(MTU);
		nt_memzero(zero, MTU);
		if (memcmp(packet, zero, MTU) == 0) {
			printk("PACKET HIT THE WIRE!!!1\n");
		}
		nt_free(zero);
	}
	
	DBG_OUT_V;
}


void ndis_packet_send_orig(const uchar *packet, int len)
{
	nd_ret ret;
	
	DBG_IN;
	
	/* aquire lock, release only when send is complete */
	KeAcquireSpinLock(&g_splock, &g_irq);
	if (g_iface_hndl[g_iface_indx] && packet) {
		nd_pack *npacket;
		NdisAllocatePacket(&ret, &npacket, g_packet_pool);
		if (NDIS_STATUS_SUCCESS == ret) {
			void *pbuf;
			nd_buf *nbuf;
			
			NdisAllocateMemory(&pbuf, len, 0, g_phymax);
			memcpy(pbuf, (void *) packet, len);
			NdisAllocateBuffer(&ret, &nbuf, g_buffer_pool, pbuf, len);
			if (NDIS_STATUS_SUCCESS == ret) {
				RESERVED(npacket)->Irp = NULL; /* so our OnSendDone() knows this is local */
				NdisChainBufferAtBack(npacket, nbuf);
				NdisSend(&ret, g_iface_hndl[g_iface_indx], npacket);
				if (ret != NDIS_STATUS_PENDING ) {
					ndis_send(g_iface_hndl[g_iface_indx], npacket, ret);
				}
			} else {
				DbgPrint("rootkit: error 0x%X NdisAllocateBuffer\n");
			}
		} else {
			DbgPrint("rootkit: error 0x%X NdisAllocatePacket\n");
		}
	}
	/* release so we can send next.. */
	KeReleaseSpinLock(&g_splock, g_irq);
	DBG_OUT_V;
}


void ndis_packet_send(const uchar *packet, int len)
{
	nd_ret   ret;
	nd_pack *npacket;
	void    *pbuf;
	nd_buf  *nbuf;
	
	DBG_IN;
	
	if (!g_iface_hndl[g_iface_indx] || !packet || !g_iface_ready) {
		
		DBG_OUT_V;
	}
	
	NdisAllocatePacket(&ret, &npacket, g_packet_pool);
	RET_ON_V_VPM((!(IS_ND_OK(ret))), "NdisAllocatePacket", ret);
	
	/* aquire lock, release only when send is complete */
	KeAcquireSpinLock(&g_splock, &g_irq);
	
	NdisAllocateMemory(&pbuf, len, 0, g_phymax);
	memcpy(pbuf, (void *) packet, len);
	NdisAllocateBuffer(&ret, &nbuf, g_buffer_pool, pbuf, len);
	if (!(IS_ND_OK(ret))) {
		KeReleaseSpinLock(&g_splock, g_irq);
		DBG_OUT_VPM("NdisAllocateBuffer", ret);
	}
	
	RSRVD_PCKT_CTX(npacket)->rp = NULL; /* so our OnSendDone() knows this is local */
	NdisChainBufferAtBack(npacket, nbuf);
	NdisSend(&ret, g_iface_hndl[g_iface_indx], npacket);
	if (ret != NDIS_STATUS_PENDING ) {
		ndis_send(g_iface_hndl[g_iface_indx], npacket, ret);
	}
	
	/* release so we can send next.. */
	KeReleaseSpinLock(&g_splock, g_irq);
	DBG_OUT_V;
}


/*** *** *** ndis routine *** *** ***/


void ndis_status(nd_hndl protobind_ctx, nd_ret s, void *sbuf, uint sbuf_len)
{
	DBG_IN;
	DBG_OUT_V;
}


void ndis_status_cmplt(nd_hndl protobind_ctx)
{
	DBG_IN;
	DBG_OUT_V;
}


void ndis_iface_open(nd_hndl protobind_ctx, nd_ret s, nd_ret err)
{
	nd_ret ret;
	nd_ret ret_req;
	nd_req ndis_req;
	ulong pcktype = NDIS_PACKET_TYPE_ALL_LOCAL; //NDIS_PACKET_TYPE_PROMISCUOUS;
	
	DBG_IN;
	
	RET_ON_ERRNT_VP(s);
	
	ndis_req.RequestType                                   =  NdisRequestSetInformation     ;
	ndis_req.DATA.SET_INFORMATION.Oid                      =  OID_GEN_CURRENT_PACKET_FILTER ;
	ndis_req.DATA.SET_INFORMATION.InformationBuffer        =  &pcktype                      ;
	ndis_req.DATA.SET_INFORMATION.InformationBufferLength  =  sizeof(ulong)                 ;
	
	NdisRequest(&ret_req, g_iface_hndl[g_iface_indx], &ndis_req);
	
	NdisAllocatePacketPool(&ret, &g_packet_pool, TRANSMIT_PACKETS, sizeof(struct packet_ctx));
	RET_ON_ERRND_VPM("NdisAllocatePacketPool: error", ret);
	
	NdisAllocateBufferPool(&ret, &g_buffer_pool, TRANSMIT_PACKETS);
	RET_ON_ERRND_VPM("NdisAllocateBufferPool: error", ret);
	
	DBG_OUT_V;
}


void ndis_iface_bind(nd_ret *s, nd_hndl bind_ctx, nd_str *devname, void *ss1, void *ss2)
{
	DBG_IN;
	DBG_OUT_V;
}


void ndis_iface_unbind(nd_ret *s, nd_hndl bind_ctx, nd_hndl *unbind_ctx)
{
	DBG_IN;
	DBG_OUT_V;
}


void ndis_iface_close(nd_hndl protobind_ctx, nd_ret s)
{
	DBG_IN;
	NdisSetEvent(&g_closew_event);
	DBG_OUT_V;
}


void ndis_reset(nd_hndl protobind_ctx, nd_ret s)
{
	DBG_IN;
	DBG_OUT_V;
}


void ndis_send(nd_hndl protobind_ctx, nd_pack *npacket, nd_ret s)
{
	nd_buf *nbuf;
	void   *pbuf;
	uint    blen;
	irp    *i;
	
	DBG_IN;
	
	KeAcquireSpinLock(&g_splock, &g_irq);
	
	i = RSRVD_PCKT_CTX(npacket)->rp;
	if (i) {
		NdisReinitializePacket(npacket);
		NdisFreePacket(npacket);
		IRP_DONE(i, 0, ND_OK);
	} else {
		NdisUnchainBufferAtFront(npacket, &nbuf);
		if (nbuf) {
			NdisQueryBuffer(nbuf, &pbuf, &blen);
			if (pbuf) {
				NdisFreeMemory(pbuf, blen, 0);
			}
			NdisFreeBuffer(nbuf);
		}
		NdisReinitializePacket(npacket);
		NdisFreePacket(npacket);
	}
	
	KeReleaseSpinLock(&g_splock, g_irq);
	
	DBG_OUT_V;
}


nt_ret ndis_recv(nd_hndl protobind_ctx, nd_hndl mac_ctx, void *hdr_buf, uint hdr_buf_len, void *labuf, uint labuf_len, uint psize)
{
	void               *mbuf;
	struct packet_ctx  *pctx;
	nd_pack            *npacket;
	nd_buf             *nbuf;
	nd_ret              ret;
	ulong               blen;
	ulong               tx_size = 0;
	uint                tx_bytes = 0;
	
	DBG_IN;
	
	tx_size = psize;
	
	if ((hdr_buf_len > ETH_HLEN) || (tx_size > (MTU - ETH_HLEN))) {
		DBG_OUT_RPM("ndis_recv: packet not accepted", NDIS_STATUS_NOT_ACCEPTED);
	}
	
	mbuf = nt_malloc(MTU - ETH_HLEN);
	if (mbuf) {
		nt_memzero(mbuf, (MTU - ETH_HLEN));
		
		NdisAllocatePacket(&ret, &npacket, g_packet_pool);
		if (NDIS_STATUS_SUCCESS == ret) {
			RSRVD_PCKT_CTX(npacket)->phdr_buf = nt_malloc(ETH_HLEN);
			if (RSRVD_PCKT_CTX(npacket)->phdr_buf) {
				nt_memzero(RSRVD_PCKT_CTX(npacket)->phdr_buf, ETH_HLEN);
				memcpy(RSRVD_PCKT_CTX(npacket)->phdr_buf, (uchar *) hdr_buf, ETH_HLEN);
				RSRVD_PCKT_CTX(npacket)->phdr_buf_len = ETH_HLEN;
				
				NdisAllocateBuffer(&ret, &nbuf, g_buffer_pool, mbuf, (MTU - ETH_HLEN));
				if (NDIS_STATUS_SUCCESS == ret) {
					RSRVD_PCKT_CTX(npacket)->pbuf = mbuf;
					
					/*this is important here we attach the buffer to the packet*/
					NdisChainBufferAtFront(npacket, nbuf);
					NdisTransferData(&(g_usrctx.status), g_iface_hndl[g_iface_indx], mac_ctx, 0, tx_size, npacket, &tx_bytes);
					
					if (ret != NDIS_STATUS_PENDING) {
						/*important to call the complete routine since it's not pending*/
						ndis_transfer(&g_usrctx, npacket, ret, tx_bytes);
					}
					
					DBG_OUT_R(ND_OK);
				}
				nt_free(RSRVD_PCKT_CTX(npacket)->phdr_buf);
			} else {
				printm("nt_malloc: error");
			}
			NdisFreePacket(npacket);
		}
		nt_free(mbuf);
	}
	DBG_OUT_R(ND_OK);
}


void ndis_recv_pckt(nd_hndl protobind_ctx, nd_pack *npacket)
{
	DBG_IN;
	DBG_OUT_V;
}


void ndis_recv_cmplt(nd_hndl protobind_ctx)
{
	DBG_IN;
	DBG_OUT_V;
}


void ndis_transfer(nd_hndl protobind_ctx, nd_pack *tx_packet , nd_ret ret, uint tx)
{
	nd_buf *nbuf;
	
	void *tbuf;
	ulong tbuf_len;
	void *hdr_tbuf;
	ulong hdr_tbuf_len;
	
	DBG_IN;
	
	tbuf         = RSRVD_PCKT_CTX(tx_packet)->pbuf         ;
	tbuf_len     = tx                                      ;
	hdr_tbuf     = RSRVD_PCKT_CTX(tx_packet)->phdr_buf     ;
	hdr_tbuf_len = RSRVD_PCKT_CTX(tx_packet)->phdr_buf_len ;
	
	/*
	aHeaderBufferP = Ethernet Header
	aBufferP tcp/ip
	*/
	
	if (tbuf && hdr_tbuf) {
		uchar *pbuf = NULL;
		pbuf = nt_malloc(hdr_tbuf_len + tbuf_len);
		if (pbuf) {
			memcpy(pbuf, hdr_tbuf, hdr_tbuf_len);
			memcpy(pbuf + hdr_tbuf_len, tbuf, tbuf_len);
			/* woei complete packet, parse it */
			ndis_packet_recv(pbuf, (hdr_tbuf_len + tbuf_len));
			nt_free(pbuf);
		}
		nt_free(tbuf);
		nt_free(hdr_tbuf);
	}
	
	NdisUnchainBufferAtFront(tx_packet, &nbuf);
	if (nbuf) {
		NdisFreeBuffer(nbuf);
	}
	
	NdisReinitializePacket(tx_packet);
	NdisFreePacket(tx_packet);
	
	g_packet_ready = 0;
	DBG_OUT_V;
}


void ndis_request(nd_hndl protobind_ctx, nd_req *nreq, nd_ret s)
{
	DBG_IN;
	DBG_OUT_V;
}


void ndis_pnp(nd_hndl protobind_ctx, nd_pnp_ev *pnpev)
{
	DBG_IN;
	DBG_OUT_V;
}


void ndis_unload(void)
{
	DBG_IN;
	DBG_OUT_V;
}


/*** *** *** device routine *** *** ***/


nt_ret dev_open(dev_obj *dobj, irp *i)
{
	DBG_IN;
	DBG_OUT_R(NT_OK);
}


nt_ret dev_read(dev_obj *dobj, irp *i)
{
	DBG_IN;
	DBG_OUT_R(NT_OK);
}


nt_ret dev_write(dev_obj *dobj, irp *i)
{
	DBG_IN;
	DBG_OUT_R(NT_OK);
}


nt_ret dev_ioctl(dev_obj *dobj, irp *i)
{
	io_stack *sl;
	ulong ctl_code;
	
	/* init associated system buffer */
	void *ubuf = IRP_ASBUF(i);
	
	DBG_IN;
	
	/* init current stack location for irp */
	sl = nt_irp_get_stack(i);
	
	/* get ioctl code */
	ctl_code = IRP_IOCTL(sl);
	
	switch (ctl_code) {
		case IOCTL_HELLO:
			if ((((struct user_irp *) ubuf)->irp_type) == IRP_IFACE) {
				iface_open((((struct user_irp *) ubuf)->irp_data), STR_DEV_LEN);
				IRP_DONE(i, 0, NT_OK);
			} else {
				printm("IOCTL >>");
				if (g_iface_ready) {
					while (!g_packet_ready) {
						continue;
					}
					nt_memzero(ubuf, IRP_IBLEN(sl));
					nt_memcpy(ubuf, g_packet, g_packet_ready);
					/* finish IRP request */
					IRP_DONE(i, g_packet_ready, NT_OK);
				} else {
					IRP_DONE(i, 0, NT_OK);
				}
				printm("IOCTL <<");
			}
			break;
		default:
			break;
	}
	
	DBG_OUT_R(NT_OK);
}


nt_ret dev_close(dev_obj *dobj, irp *i)
{
	DBG_IN;
	DBG_OUT_R(NT_OK);
}


/*** *** *** init routine *** *** ***/


void init_sending(void)
{
	uchar *pckt = nt_malloc(MTU);
	
	DBG_IN;
	
	nt_memzero(pckt, MTU);
	ndis_packet_send(pckt, MTU);
	nt_free(pckt);
	
	DBG_OUT_V;
}


void iface_open(wchar_t *iface_name, int iface_len)
{
	//g_iface_name = L"\\Device\\{BDB421B0-4B37-4AA2-912B-3AA05F8A0829}" // 38
	
	nd_ret ret, err;
	ustring ifname, tmp;
	uint mindex = 0;
	// uchar *tmp = NULL;
	
	nd_medm marray = NdisMedium802_3; // specifies a ethernet network
	
	DBG_IN;
	
	//printm("init global adapter name");
	
	DbgPrint("DEVICE(input  s) == %s\n",  iface_name);
	DbgPrint("DEVICE(input ws) == %ws\n", iface_name);
	
	/* WORK
	printm("init local adapter name");
	nt_init_ustring(&ifname, iface_name);
	
	if (ifname.Buffer) {
	
	DbgPrint("ifname  s ==  %s\n", ifname.Buffer);
	DbgPrint("ifname ws) == %ws\n", ifname.Buffer);
	} else {
		DbgPrint("NULL!!1\n");
	}
	*/
	
	/* CHECK */
	/*
	printm("init local adapter name");
	nt_init_ustring(&g_iface_name, iface_name);
	
	if (ifname.Buffer) {
	
	DbgPrint("g ifname  s ==  %s\n", g_iface_name.Buffer);
	DbgPrint("g ifname ws) == %ws\n", g_iface_name.Buffer);
	} else {
		DbgPrint("NULL!!1\n");
	}
	
	DbgPrint("g dev path  s ==  %s\n", g_devpath);
	DbgPrint("g dev path ws == %ws\n", g_devpath);
	DbgPrint("g dev link  s ==  %s\n", g_devlink);
	DbgPrint("g dev link ws == %ws\n", g_devlink);
	*/

	/*
	g_iface_name.Length = 0;
	g_iface_name.MaximumLength = iface_len + g_dev_prefix.Length + sizeof(UNICODE_NULL);
	g_iface_name.Buffer = nt_malloc(g_iface_name.MaximumLength);

	if (!(g_iface_name.Buffer)) {
		printdbg("MEMORY: NULL\n");
	}
	*/
	//nt_init_ustring(g_iface_name, &g_dev_prefix);
	/*
	RtlAppendUnicodeStringToString(&g_iface_name, &g_dev_prefix);
	RtlAppendUnicodeToString(&g_iface_name, iface_name + g_dev_prefix.Length / sizeof(WCHAR));
	DbgPrint("DEVICE(global  s) == %s\n", g_iface_name.Buffer);
	*/
	
	/*
	tmp = nt_malloc(iface_len + g_dev_prefix.Length + sizeof(UNICODE_NULL));
	if (!(tmp)) {
		printdbg("MEMORY 2: NULL\n");
		return;
	}
	nt_memzero(tmp, (iface_len + 12 + sizeof(UNICODE_NULL)));
	memcpy(tmp, "\\Device\\", 10);
	DbgPrint("DEVICE(tmp1 s) == %s\n", tmp);
	strcat(tmp, iface_name);
	DbgPrint("DEVICE(tmp2 s) == %s\n", tmp);
	strcat(tmp, '\0');
	DbgPrint("DEVICE(tmp3 s) == %s\n", tmp);
	*/
	
	/*
	printm("init global adapter name");
	nt_init_ustring(&g_iface_name, iface_name);
	
	DbgPrint("DEVICE(global  s) == %s\n", g_iface_name.Buffer);
	DbgPrint("DEVICE(global ws) == %ws\n", g_iface_name.Buffer);
	*/
	/*
	g_iface_ready = 1;
	*/
	
	/*
	DbgPrint("iface_name  s) ==  %s\n", iface_name);
	DbgPrint("iface_name ws) == %ws\n", iface_name);
	*/
	printm("init local adapter name");
	nt_init_ustring(&ifname, iface_name);
	
	DbgPrint("ifname  s) ==  %s\n", ifname.Buffer);
	DbgPrint("ifname ws) == %ws\n", ifname.Buffer);
	
	
	//nt_init_ustring(&ifname, L"\\Device\\{BDB421B0-4B37-4AA2-912B-3AA05F8A0829}");
	//nt_init_ustring(&ifname, L"\\Device\\{2D2E989B-6153-4787-913D-807779793B27}");
	//nt_init_ustring(&ifname, L"\\Device\\{449F621A-04BC-4896-BBCB-7A93708EA9B8}");
	/* taken from:
	 * \HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{...}
	 */
	
	
	printm("opening adapter");
	NdisOpenAdapter(&ret, &err, &g_iface_hndl[g_iface_indx], &mindex, &marray, 1, g_proto_hndl, &g_usrctx, &ifname, 0, NULL);
	if (!(IS_ND_OK(ret))) {
		if (!(IS_NT_OK(ret))) {
			printmd("NdisOpenAdapter: error", ret);
			if (ret = NDIS_STATUS_ADAPTER_NOT_FOUND) {
				printm("NdisOpenAdapter: adapter not found");
			}
			
			NdisDeregisterProtocol(&ret, g_proto_hndl);
			if (!(IS_NT_OK(ret))) {
				printm("NdisDeregisterProtocol: error");
			}
			return NT_ERR;
		}
	}
	
	ndis_iface_open(&g_usrctx, ret, ND_OK);
	
	init_sending();
}


void iface_close()
{
	nd_ret ret;
	
	DBG_IN;
	
	printm("closing adapter for network interface");
	NdisCloseAdapter(&ret, g_iface_hndl[g_iface_indx]);
	if (ret == NDIS_STATUS_PENDING) {
		printm("waiting ndis event");
		NdisWaitEvent(&g_closew_event, 0);
	}
	
	DBG_OUT;
}


nt_ret init_ndis(mod_obj *mobj)
{
	nd_ret ret, err;
	nd_proto proto;
	ustring ifname;
	uint mindex = 0;
	
	//This string must match that specified in the registery (under Services) when the protocol was installed
	nd_str pname   = NDIS_STRING_CONST(PROTONAME);
	nd_medm marray = NdisMedium802_3; // specifies a ethernet network
	
	DBG_IN;
	
	printm("init ndis event");
	NdisInitializeEvent(&g_closew_event);
	
	nt_memzero(&proto, sizeof(nd_proto));
	
	printm("init proto");
	proto.MajorNdisVersion             = PROTO_NDIS_MAJOR    ;
	proto.MinorNdisVersion             = PROTO_NDIS_MINOR    ;
	proto.Name                         = pname               ;
	proto.Reserved                     = 0                   ;
	
	proto.StatusHandler                =  ndis_status        ;
	proto.StatusCompleteHandler        =  ndis_status_cmplt  ;
	
	proto.OpenAdapterCompleteHandler   =  ndis_iface_open    ;
	proto.BindAdapterHandler           =  ndis_iface_bind    ;
	proto.UnbindAdapterHandler         =  ndis_iface_unbind  ;
	proto.CloseAdapterCompleteHandler  =  ndis_iface_close   ;
	
	proto.ResetCompleteHandler         =  ndis_reset         ;
	proto.SendCompleteHandler          =  ndis_send          ;
	proto.ReceiveHandler               =  ndis_recv          ;
	proto.ReceivePacketHandler         =  ndis_recv_pckt     ;
	proto.ReceiveCompleteHandler       =  ndis_recv_cmplt    ;
	proto.TransferDataCompleteHandler  =  ndis_transfer      ;
	proto.RequestCompleteHandler       =  ndis_request       ;
	proto.PnPEventHandler              =  ndis_pnp           ;
	proto.UnloadHandler                =  ndis_unload        ;
	
	printm("register proto");
	NdisRegisterProtocol(&ret, &g_proto_hndl, &proto, sizeof(nd_proto));
	RET_ON_ERRND_RPM("NdisRegisterProtocol: error", ret);
	
	/*
	printm("waiting iface name");
	while (!g_iface_ready) {
		continue;
	}
	*/
	
	/*
	printm("init adapter name");
	nt_init_ustring(&ifname, g_iface_name->Buffer);
	//nt_init_ustring(&ifname, L"\\Device\\{BDB421B0-4B37-4AA2-912B-3AA05F8A0829}");
	//nt_init_ustring(&ifname, L"\\Device\\{2D2E989B-6153-4787-913D-807779793B27}");
	//nt_init_ustring(&ifname, L"\\Device\\{449F621A-04BC-4896-BBCB-7A93708EA9B8}");
	*/
	/* taken from:
	 * \HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{...}
	 */
	
	/*
	printm("opening adapter");
	NdisOpenAdapter(&ret, &err, &g_iface_hndl, &mindex, &marray, 1, g_proto_hndl, &g_usrctx, &ifname, 0, NULL);
	if (!(IS_ND_OK(ret))) {
		if (!(IS_NT_OK(ret))) {
			printmd("NdisOpenAdapter: error", ret);
			if (ret = NDIS_STATUS_ADAPTER_NOT_FOUND) {
				printm("NdisOpenAdapter: adapter not found");
			}
			
			NdisDeregisterProtocol(&ret, g_proto_hndl);
			if (!(IS_NT_OK(ret))) {
				printm("NdisDeregisterProtocol: error");
			}
			return NT_ERR;
		}
	}
	
	ndis_iface_open(&g_usrctx, ret, ND_OK);
	*/

	printm("preparing buffer for packet");
	g_packet = (uchar *) nt_malloc(g_packet_size);
	RET_ON_NULL(g_packet);
	nt_memzero(g_packet, g_packet_size);
	
	KeInitializeSpinLock(&g_splock);
	
	DBG_OUT_R(NT_OK);
}


nt_ret init_device(mod_obj *mobj)
{
	nt_ret   ret;
	ustring  devname_path;
	ustring  devname_link;
	
	DBG_IN;
	
	// We set up the name and symbolic link in Unicode
	printm("init strings for devices");
	nt_init_ustring(&devname_path, g_devpath);
	nt_init_ustring(&devname_link, g_devlink);
	
	printm("creating device");
	ret = nt_creat(mobj, &devname_path, &g_device);
	RET_ON_ERRNT_RP(ret);
	
	/* TODO: DEVICE_EXTENSION management */
	
	printm("creating symlink for device");
	ret = nt_creat_link(&devname_link, &devname_path);
	RET_ON_ERRNT_RP(ret);
	
	printm("init device callbacks");
	mobj->MajorFunction[IRP_MJ_CREATE]         = dev_open  ;
	mobj->MajorFunction[IRP_MJ_READ]           = dev_read  ;
	mobj->MajorFunction[IRP_MJ_WRITE]          = dev_write ;
	mobj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = dev_ioctl ;
	mobj->MajorFunction[IRP_MJ_CLOSE]          = dev_close ;
	
	DBG_OUT_R(NT_OK);
}


nt_ret init_ctx(void)
{
	DBG_IN;
/*
	g_modctx.device_path = g_devpath;
	g_modctx.device_link = g_devlink;
	g_modctx.packet = NULL;
	g_modctx.packet_size = 64 * 1024;
	g_modctx.packet_ready = 0;
*/
	DBG_OUT_R(NT_OK);
}


/*** *** *** clean up on exit routine *** *** ***/


void exit_ndis(mod_obj *mobj)
{
	nd_ret ret;
	
	DBG_IN;
	
	printm("resetting ndis event");
	NdisResetEvent(&g_closew_event);
	
	iface_close();
	
	printm("disabling protocol");
	NdisDeregisterProtocol(&ret, g_proto_hndl);
	
	if (!(IS_NT_OK(ret))) {
		printm("NdisDeregisterProtocol: error");
	}
	
	DBG_OUT;
}


void exit_device(mod_obj *mobj)
{
	ustring  devname_link;
	
	DBG_IN;
	
	printm("init string for device");
	nt_init_ustring(&devname_link, g_devlink);
	
	printm("removing device link");
	nt_unlink_link(&devname_link);
	/*
	printm("removing device path");
	nt_unlink_dev(g_device);
	*/
	
	printm("removing device object");
	nt_unlink_dev(mobj->DeviceObject);
	
	DBG_OUT;
}


void exit_module(mod_obj *mobj)
{
	DBG_IN;
	printm("cleaning up ndis");
	exit_ndis(mobj);
	printm("cleaning up devices");
	exit_device(mobj);
	DBG_OUT;
}


/*** *** *** main driver entry point *** *** ***/


nt_ret init_module(mod_obj *mobj)
{
	nt_ret ret;
	
	DBG_IN;
	
	printm("init unload module callback");
	mobj->DriverUnload = exit_module;
	
	printm("init device");
	ret = init_ctx();
	RET_ON_ERRNT_RP(ret);
	
	printm("init device");
	ret = init_device(mobj);
	RET_ON_ERRNT_RP(ret);
	
	printm("init ndis");
	ret = init_ndis(mobj);
	RET_ON_ERRNT_RP(ret);
	
	DBG_OUT_R(NT_OK);
}


nt_ret DriverEntry(mod_obj *mobj, ustring *regpath)
{
	DBG_IN;
	DBG_OUT_R(init_module(mobj));
}


