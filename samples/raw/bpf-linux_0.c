//4659l5

//Listing 5. Needs caption

#include <stdio.h>
#include <string.h>
#include <errno.h>  
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>  
#include <linux/in.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <linux/filter.h>
#include <sys/ioctl.h>

int main(int argc, char **argv) {
  int sock, n;
  char buffer[2048];
  unsigned char *iphead, *ethhead;
  struct ifreq ethreq;

  /*
    udp and host 192.168.9.10 and src port 5000
    (000) ldh      [12]
    (001) jeq      #0x800           jt 2        jf 14
    (002) ldb      [23]
    (003) jeq      #0x11            jt 4        jf 14
    (004) ld       [26]
    (005) jeq      #0xc0a8090a      jt 8        jf 6
    (006) ld       [30]
    (007) jeq      #0xc0a8090a      jt 8        jf 14
    (008) ldh      [20]
    (009) jset     #0x1fff          jt 14       jf 10
    (010) ldxb     4*([14]&0xf)
    (011) ldh      [x + 14]
    (012) jeq      #0x1388          jt 13       jf 14
    (013) ret      #68
    (014) ret      #0
  */
  struct sock_filter BPF_code[]= { /*
    { 0x28, 0, 0, 0x0000000c },
    { 0x15, 0, 12, 0x00000800 },
    { 0x30, 0, 0, 0x00000017 },
    { 0x15, 0, 10, 0x00000011 },
    { 0x20, 0, 0, 0x0000001a },
    { 0x15, 2, 0, 0xc0a88009 },host ip
    { 0x20, 0, 0, 0x0000001e },
    { 0x15, 0, 6, 0xc0a88009 }, host ip
    { 0x28, 0, 0, 0x00000014 },
    { 0x45, 4, 0, 0x00001fff },
    { 0xb1, 0, 0, 0x0000000e },
    { 0x48, 0, 0, 0x0000000e },
    { 0x15, 0, 1, 0x00001388 },
    { 0x6, 0, 0, 0x00000044 },
    { 0x6, 0, 0, 0x00000000 }*/
{ 0x6, 0, 0, 0x0000ffff }
  };                            
  struct sock_fprog Filter; 
    
  Filter.len = 1; // 15
  Filter.filter = BPF_code;
  
  if ( (sock=socket(PF_PACKET, SOCK_RAW, 
                    htons(ETH_P_IP)))<0) {
    perror("socket");
    exit(1);
  }

  /* Set the network card in promiscuos mode */
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
 
  /* Attach the filter to the socket */
  if(setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, 
                &Filter, sizeof(Filter))<0){
    perror("setsockopt");
    close(sock);
    exit(1);
  }
 
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

    iphead = buffer+14; /* Skip Ethernet  header */
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

