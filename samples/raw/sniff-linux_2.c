
#include <stdio.h>
#include <string.h>
#include <errno.h>  
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>  
#include <linux/in.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <sys/ioctl.h>

int main(int argc, char **argv) {
  int sock, n;
  char buffer[2048];
  unsigned char *iphead, *ethhead;
  struct ifreq ethreq;
  
  if ( (sock=socket(PF_PACKET, SOCK_RAW, 
                    htons(ETH_P_IP)))<0) {
    perror("socket");
    exit(1);
  }

  /* Set the network card in promiscuos mode */
  /*
  strncpy(ethreq.ifr_name,"eth0",IFNAMSIZ);
  if (ioctl(sock,SIOCGIFFLAGS,&ethreq)==-1) {
    perror("ioctl");
    close(sock);
    exit(1);
  }
  ethreq.ifr_flags|=IFF_PROMISC;
  if (ioctl(sock,SIOCSIFFLAGS,&ethreq)==-1) {
    perror("ioctl");
    close(sock);
    exit(1);
  }
  */
  
  while (1) {
    printf("----------\n");
    n = recvfrom(sock,buffer,2048,0,NULL,NULL);
    printf("%d bytes read\n",n);

    /* Check to see if the packet contains at least 
     * complete Ethernet (14), IP (20) and TCP/UDP 
     * (8) headers.
     */
    if (n<42) {
      perror("recvfrom():");
      printf("Incomplete packet (errno is %d)\n",
             errno);
      close(sock);
      exit(0);
    }

    ethhead = buffer;
    printf("Source MAC address: "
           "%02x:%02x:%02x:%02x:%02x:%02x\n",
           ethhead[0],ethhead[1],ethhead[2],
           ethhead[3],ethhead[4],ethhead[5]);
    printf("Destination MAC address: "
           "%02x:%02x:%02x:%02x:%02x:%02x\n",
           ethhead[6],ethhead[7],ethhead[8],
           ethhead[9],ethhead[10],ethhead[11]);

    iphead = buffer+14; /* Skip Ethernet header */
    if (*iphead==0x45) { /* Double check for IPv4
                          * and no options present */
      printf("Source host %d.%d.%d.%d\n",
             iphead[12],iphead[13],
             iphead[14],iphead[15]);
      printf("Dest host %d.%d.%d.%d\n",
             iphead[16],iphead[17],
             iphead[18],iphead[19]);
      printf("Source,Dest ports %d,%d\n",
             (iphead[20]<<8)+iphead[21],
             (iphead[22]<<8)+iphead[23]);
      printf("Layer-4 protocol %d\n",iphead[9]);
    }
  }
  
}

