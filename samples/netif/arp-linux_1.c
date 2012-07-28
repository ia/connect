
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/in.h>
#include <net/if.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if_arp.h>

char *mac_ntoa(unsigned char *ptr){
    static char address[30];

    sprintf(address, "%02X:%02X:%02X:%02X:%02X:%02X",
        ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);

    return(address);
} /* End of mac_ntoa */

int mac_aton(char *addr, unsigned char *ptr){
    int i, v[6];
    if((i = sscanf(addr, "%x:%x:%x:%x:%x:%x", &v[0], &v[1], &v[2], &v[3],
            &v[4], &v[5])) !=6){

        fprintf(stderr, "arp: invalid Ethernet address '%s'\n", addr);
        return(1);
    } /* End of If*/

    for(i = 0; i < 6; i++){
        ptr[i] = v[i];
    } /* End of For */

    return(0);
}

int main(int argc, char* argv[]){
    if(argc < 3 || argc > 4){
        fprintf(stderr,"usage: %s <ip_addr> <hw_addr> [temp|pub|perm|trail]\n",
            argv[0]);
        fprintf(stderr, "default: temp.\n");
        exit(-1);
    } /* End of If */

    int s, flags;
    char *host = argv[1];

    struct arpreq req;
    struct hostent *hp;
    struct sockaddr_in *sin;

    bzero((caddr_t)&req, sizeof(req)); /* caddr_t is not really needed. */

    sin = (struct sockaddr_in *)&req.arp_pa;
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = inet_addr(host);

    if(sin->sin_addr.s_addr ==-1){
        if(!(hp = gethostbyname(host))){
            fprintf(stderr, "arp: %s ", host);
            herror((char *)NULL);
            return(-1);
        } /* End of If */
        bcopy((char *)hp->h_addr,
            (char *)&sin->sin_addr, sizeof(sin->sin_addr));
    } /* End of If */

    if(mac_aton(argv[2], req.arp_ha.sa_data)){ /* If address is valid... */
        return(-1);
    }

    argc -=2;
    argv +=2;

    flags = ATF_PERM | ATF_COM;

    while(argc-- > 0){
        if(!(strncmp(argv[0], "temp", 4))){
            flags &= ~ATF_PERM;
        } else if(!(strncmp(argv[0], "pub", 3))){
            flags |= ATF_PUBL;
        } else if(!(strncmp(argv[0], "trail", 5))){
            flags |= ATF_USETRAILERS;
        } else if(!(strncmp(argv[0], "dontpub", 7))){ /* Not working yet */
            flags |= ATF_DONTPUB;
        } else if(!(strncmp(argv[0], "perm", 4))){
            flags = ATF_PERM;
        } else {
            flags &= ~ATF_PERM;
        } /* End of Else*/
    argv++;
    }/* End of While */

    req.arp_flags = flags; /* Finally, asign the flags to the structure */
    strcpy(req.arp_dev, "eth0"); /* Asign the device.  */

    if((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
        perror("socket() failed.");
        exit(-1);
    } /* End of If */

    if(ioctl(s, SIOCGARP, (caddr_t)&req) <0){ /* caddr_t not really needed. */
        perror(host);
        exit(-1);
    } /* End of If */

    printf("ARP cache entry successfully added.\n");
    close(s);
    return(0);
}

