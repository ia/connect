
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <time.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/sockios.h>

#ifndef __GLIBC__
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#endif

/* *** MII.H *** */

/* network interface ioctl's for MII commands */
#ifndef SIOCGMIIPHY
#warning "SIOCGMIIPHY is not defined by your kernel source"
#define SIOCGMIIPHY (SIOCDEVPRIVATE)   /*  Read from current PHY       */
#define SIOCGMIIREG (SIOCDEVPRIVATE+1) /*  Read any PHY register       */
#define SIOCSMIIREG (SIOCDEVPRIVATE+2) /*  Write any PHY register      */
#define SIOCGPARAMS (SIOCDEVPRIVATE+3) /*  Read operational parameters */
#define SIOCSPARAMS (SIOCDEVPRIVATE+4) /*  Set operational parameters  */
#endif

#include <linux/types.h>

/* This data structure is used for all the MII ioctl's */
struct mii_data {
	__u16  phy_id;
	__u16  reg_num;
	__u16  val_in;
	__u16  val_out;
};

/* Basic Mode Control Register */
#define MII_BMCR		0x00
#define  MII_BMCR_RESET		0x8000
#define  MII_BMCR_LOOPBACK	0x4000
#define  MII_BMCR_100MBIT	0x2000
#define  MII_BMCR_AN_ENA	0x1000
#define  MII_BMCR_ISOLATE	0x0400
#define  MII_BMCR_RESTART	0x0200
#define  MII_BMCR_DUPLEX	0x0100
#define  MII_BMCR_COLTEST	0x0080
#define  MII_BMCR_SPEED1000	0x0040

/* Basic Mode Status Register */
#define MII_BMSR		0x01
#define  MII_BMSR_CAP_MASK	0xf800
#define  MII_BMSR_100BASET4	0x8000
#define  MII_BMSR_100BASETX_FD	0x4000
#define  MII_BMSR_100BASETX_HD	0x2000
#define  MII_BMSR_10BASET_FD	0x1000
#define  MII_BMSR_10BASET_HD	0x0800
#define  MII_BMSR_NO_PREAMBLE	0x0040
#define  MII_BMSR_AN_COMPLETE	0x0020
#define  MII_BMSR_REMOTE_FAULT	0x0010
#define  MII_BMSR_AN_ABLE	0x0008
#define  MII_BMSR_LINK_VALID	0x0004
#define  MII_BMSR_JABBER	0x0002
#define  MII_BMSR_EXT_CAP	0x0001

#define MII_PHY_ID1		0x02
#define MII_PHY_ID2		0x03

/* Auto-Negotiation Advertisement Register */
#define MII_ANAR		0x04
/* Auto-Negotiation Link Partner Ability Register */
#define MII_ANLPAR		0x05
#define  MII_AN_NEXT_PAGE	0x8000
#define  MII_AN_ACK		0x4000
#define  MII_AN_REMOTE_FAULT	0x2000
#define  MII_AN_ABILITY_MASK	0x07e0
#define  MII_AN_FLOW_CONTROL	0x0400
#define  MII_AN_100BASET4	0x0200
#define  MII_AN_100BASETX_FD	0x0100
#define  MII_AN_100BASETX_HD	0x0080
#define  MII_AN_10BASET_FD	0x0040
#define  MII_AN_10BASET_HD	0x0020
#define  MII_AN_PROT_MASK	0x001f
#define  MII_AN_PROT_802_3	0x0001

/* Auto-Negotiation Expansion Register */
#define MII_ANER		0x06
#define  MII_ANER_MULT_FAULT	0x0010
#define  MII_ANER_LP_NP_ABLE	0x0008
#define  MII_ANER_NP_ABLE	0x0004
#define  MII_ANER_PAGE_RX	0x0002
#define  MII_ANER_LP_AN_ABLE	0x0001

#define MII_CTRL1000		0x09
#define   MII_BMCR2_1000FULL	0x0200
#define   MII_BMCR2_1000HALF	0x0100

#define MII_STAT1000		0x0a
#define   MII_LPA2_1000LOCALOK  0x2000
#define   MII_LPA2_1000REMRXOK	0x1000
#define   MII_LPA2_1000FULL	0x0800
#define   MII_LPA2_1000HALF	0x0400

/* Last register we need for show_basic_mii() */
#define MII_BASIC_MAX          (MII_STAT1000+1)

/* *** *** *** *** */

/* Maximum # of interfaces */
#define MAX_ETH                 8

/* Table of known MII's */
static const struct {
	u_short  id1, id2;
	char    *name;
} mii_id[] = {
	{ 0x0022, 0x5610, "AdHoc AH101LF"         },
	{ 0x0022, 0x5520, "Altimata AC101LF"      },
	{ 0x0000, 0x6b90, "AMD 79C901A HomePNA"   },
	{ 0x0000, 0x6b70, "AMD 79C901A 10baseT"   },
	{ 0x0181, 0xb800, "Davicom DM9101"        },
	{ 0x0043, 0x7411, "Enable EL40-331"       },
	{ 0x0015, 0xf410, "ICS 1889"              },
	{ 0x0015, 0xf420, "ICS 1890"              },
	{ 0x0015, 0xf430, "ICS 1892"              },
	{ 0x02a8, 0x0150, "Intel 82555"           },
	{ 0x7810, 0x0000, "Level One LXT970/971"  },
	{ 0x2000, 0x5c00, "National DP83840A"     },
	{ 0x0181, 0x4410, "Quality QS6612"        },
	{ 0x0282, 0x1c50, "SMSC 83C180"           },
	{ 0x0300, 0xe540, "TDK 78Q2120"           },
	{ 0x0141, 0x0c20, "Yukon 88E1011"         },
	{ 0x0141, 0x0cc0, "Yukon-EC 88E1111"      },
	{ 0x0141, 0x0c90, "Yukon-2 88E1112"       },
};
#define NMII (sizeof(mii_id)/sizeof(mii_id[0]))

/* AF_INET socket for ioctl() calls. */
static int skfd = -1;

static struct ifreq ifr;

const struct {
	char    *name;
	u_short  value[2];
} media[] = {
	/* The order through 100baseT4 matches bits in the BMSR */
	{ "10baseT-HD"  , {   MII_AN_10BASET_HD                          } },
	{ "10baseT-FD"  , {   MII_AN_10BASET_FD                          } },
	{ "100baseTx-HD", {   MII_AN_100BASETX_HD                        } },
	{ "100baseTx-FD", {   MII_AN_100BASETX_FD                        } },
	{ "100baseT4"   , {   MII_AN_100BASET4                           } },
	{ "100baseTx"   , {   MII_AN_100BASETX_FD  | MII_AN_100BASETX_HD } },
	{ "10baseT"     , {   MII_AN_10BASET_FD    | MII_AN_10BASET_HD   } },
	{ "1000baseT-HD", {0, MII_BMCR2_1000HALF                         } },
	{ "1000baseT-FD", {0, MII_BMCR2_1000FULL                         } },
	{ "1000baseT"   , {0, MII_BMCR2_1000HALF   | MII_BMCR2_1000FULL  } },
};
#define NMEDIA (sizeof(media)/sizeof(media[0]))

/* *** *** */

static const char *media_list(unsigned mask, unsigned mask2, int best)
{
	static char buf[100];
	int i;
	*buf = '\0';
	
	if (mask & MII_BMCR_SPEED1000) {
		
		if (mask2 & MII_BMCR2_1000HALF) {
			strcat(buf, " ");
			strcat(buf, "1000baseT-HD");
			if (best) {
				goto out;
			}
		}
		
		if (mask2 & MII_BMCR2_1000FULL) {
			strcat(buf, " ");
			strcat(buf, "1000baseT-FD");
			if (best) {
				goto out;
			}
		}
		
	}
	
	mask >>= 5;
	for (i = 4; i >= 0; i--) {
		if (mask & (1<<i)) {
			strcat(buf, " ");
			strcat(buf, media[i].name);
			if (best) {
				break;
			}
		}
	}
	
	out:
		if (mask & (1<<5)) {
			strcat(buf, " flow-control");
		}
	
	return buf;
}

static int mdio_read(int skfd, int location)
{
	struct mii_data *mii = (struct mii_data *)&ifr.ifr_data;
	mii->reg_num = location;
	
	if (ioctl(skfd, SIOCGMIIREG, &ifr) < 0) {
		//fprintf(stderr, "SIOCGMIIREG on %s failed: %s\n", ifr.ifr_name, strerror(errno));
		return -1;
	}
	
	return mii->val_out;
}


int show_basic_mii(int sock, int phy_id)
{
	int verbose = 0;
	char buf[100];
	int i, mii_val[32];
	unsigned bmcr, bmsr, advert, lkpar, bmcr2, lpa2;
	
	/* Some bits in the BMSR are latched, but we can't rely on being the only reader, so only the current values are meaningful */
	mdio_read(sock, MII_BMSR);
	for (i = 0; i < ((verbose > 1) ? 32 : MII_BASIC_MAX); i++) {
		mii_val[i] = mdio_read(sock, i);
	}
	
	if (mii_val[MII_BMCR] == 0xffff  || mii_val[MII_BMSR] == 0x0000) {
		fprintf(stderr, "  No MII transceiver present!.\n");
		return -1;
	}
	
	/* Descriptive rename. */
	bmcr = mii_val[MII_BMCR];
	bmsr = mii_val[MII_BMSR];
	advert = mii_val[MII_ANAR];
	lkpar = mii_val[MII_ANLPAR];
	bmcr2 = mii_val[MII_CTRL1000];
	lpa2 = mii_val[MII_STAT1000];
	
	sprintf(buf, "%s: ", ifr.ifr_name);
	if (bmcr & MII_BMCR_AN_ENA) {
		if (bmsr & MII_BMSR_AN_COMPLETE) {
			if (advert & lkpar) {
				strcat(buf, (lkpar & MII_AN_ACK) ? "negotiated" : "no autonegotiation,");
				strcat(buf, media_list(advert & lkpar, bmcr2 & lpa2>>2, 1));
				strcat(buf, ", ");
			} else {
				strcat(buf, "autonegotiation failed, ");
			}
		} else if (bmcr & MII_BMCR_RESTART) {
			strcat(buf, "autonegotiation restarted, ");
		}
	} else {
		sprintf(buf+strlen(buf), "%s Mbit, %s duplex, ",
				((bmcr2 & (MII_BMCR2_1000HALF | MII_BMCR2_1000FULL)) & lpa2 >> 2) ? "1000" : (bmcr & MII_BMCR_100MBIT) ? "100" : "10",
				(bmcr & MII_BMCR_DUPLEX) ? "full" : "half");
	}
	strcat(buf, (bmsr & MII_BMSR_LINK_VALID) ? "link ok" : "no link");
	
	printf("%s\n", buf);
	
	if (verbose > 1) {
		printf("  registers for MII PHY %d: ", phy_id);
		for (i = 0; i < 32; i++) {
			printf("%s %4.4x", ((i % 8) ? "" : "\n   "), mii_val[i]);
		}
		printf("\n");
	}
	
	if (verbose) {
		
		printf("  product info: ");
		
		for (i = 0; i < NMII; i++) {
			if ((mii_id[i].id1 == mii_val[2]) && (mii_id[i].id2 == (mii_val[3] & 0xfff0))) {
				break;
			}
		}
		
		if (i < NMII) {
			printf("%s rev %d\n", mii_id[i].name, mii_val[3]&0x0f);
		} else {
			printf("vendor %02x:%02x:%02x, model %d rev %d\n",
				mii_val[2]>>10, (mii_val[2]>>2)&0xff,
				((mii_val[2]<<6)|(mii_val[3]>>10))&0xff,
				(mii_val[3]>>4)&0x3f, mii_val[3]&0x0f);
		}
		
		printf("  basic mode:   ");
		
		if (bmcr & MII_BMCR_RESET) {
			printf("software reset, ");
		}
		
		if (bmcr & MII_BMCR_LOOPBACK) {
			printf("loopback, ");
		}
		
		if (bmcr & MII_BMCR_ISOLATE) {
			printf("isolate, ");
		}
		
		if (bmcr & MII_BMCR_COLTEST) {
			printf("collision test, ");
		}
		
		if (bmcr & MII_BMCR_AN_ENA) {
			printf("autonegotiation enabled\n");
		} else {
			printf("%s Mbit, %s duplex\n",
				(bmcr & MII_BMCR_100MBIT) ? "100" : "10",
				(bmcr & MII_BMCR_DUPLEX) ? "full" : "half");
		}
		
		printf("  basic status: ");
		
		if (bmsr & MII_BMSR_AN_COMPLETE) {
			printf("autonegotiation complete, ");
		} else if (bmcr & MII_BMCR_RESTART) {
			printf("autonegotiation restarted, ");
		}
		
		if (bmsr & MII_BMSR_REMOTE_FAULT) {
			printf("remote fault, ");
		}
		
		printf((bmsr & MII_BMSR_LINK_VALID) ? "link ok" : "no link");
		
		printf("\n  capabilities:%s", media_list(bmsr >> 6, bmcr2, 0));
		printf("\n  advertising: %s", media_list(advert, lpa2 >> 2, 0));
		
		if (lkpar & MII_AN_ABILITY_MASK) {
			printf("\n  link partner:%s", media_list(lkpar, bmcr2, 0));
		}
		
		printf("\n");
	}
	
	fflush(stdout);
	
	return 0;
}

static int do_one_xcvr(int skfd, char *ifname, int maybe)
{
	struct mii_data *mii = (struct mii_data *) &ifr.ifr_data;
	
	/* Get the vitals from the interface. */
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(skfd, SIOCGMIIPHY, &ifr) < 0) {
		if (!maybe || (errno != ENODEV)) {
			fprintf(stderr, "SIOCGMIIPHY on '%s' failed: %s\n", ifname, strerror(errno));
			return 1;
		}
	}
	
	show_basic_mii(skfd, mii->phy_id);
	
	return 0;
}

/* *** *** */

int main(int argc, const char *argv[])
{
	int i, c, ret, errflag = 0;
	char s[6];
	unsigned ctrl1000 = 0;
	
	/* Open a basic socket. */
	if ((skfd = socket(AF_INET, SOCK_DGRAM,0)) < 0) {
		perror("socket");
		exit(-1);
	}
	
	if (argc != 2) {
		printf("Usage: ifmedia ethN\n");
		return 1;
	}
	
	//char *if_name = "eth0";
	do_one_xcvr(skfd, argv[1], 0);
	
	return 0;
}

/* *** *** */

