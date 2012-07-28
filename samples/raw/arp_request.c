/*  Copyright (C) 2011  P.D. Buchan (pdbuchan@yahoo.com)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

// Send an IPv4 ARP packet via raw socket at the link layer (ethernet frame).
// Values set for ARP request.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset(), and memcpy()

#include <netdb.h>            // struct addrinfo
#include <sys/types.h>        // needed for socket()
#include <sys/socket.h>       // needed for socket()
#include <netinet/in.h>       // IPPROTO_RAW
#include <netinet/ip.h>       // IP_MAXPACKET (which is 65535)
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.
#include <net/if.h>           // struct ifreq
#include <linux/if_ether.h>   // ETH_P_ARP = 0x0806
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>

#include <errno.h>            // errno, perror()

// Define a struct for ARP header
typedef struct _arp_hdr arp_hdr;
struct _arp_hdr {
  unsigned short htype;
  unsigned short ptype;
  unsigned char hlen;
  unsigned char plen;
  unsigned short opcode;
  unsigned char sender_mac[6];
  unsigned char sender_ip[4];
  unsigned char target_mac[6];
  unsigned char target_ip[4];
};

// Define some constants.
#define IP4_HDRLEN 20         // IPv4 header length
#define ARP_HDRLEN 28         // ARP header length
#define ARPOP_REQUEST 1       // Taken from <linux/if_arp.h>

int
main (int argc, char **argv)
{
  int i, status, frame_length, sd, bytes;
  char *interface, *target, *src_ip;
  arp_hdr arphdr;
  unsigned char *src_mac, *dst_mac, *ether_frame;
  struct addrinfo hints, *res;
  struct sockaddr_in *ipv4;
  struct sockaddr_ll device;
  struct ifreq ifr;
  void *tmp;

// Allocate memory for various arrays.

  tmp = (unsigned char *) malloc (6 * sizeof (unsigned char));
  if (tmp != NULL) {
    src_mac = tmp;
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array 'src_mac'.\n");
    exit (EXIT_FAILURE);
  }
  memset (src_mac, 0, 6);

  tmp = (unsigned char *) malloc (6 * sizeof (unsigned char));
  if (tmp != NULL) {
    dst_mac = tmp;
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array 'dst_mac'.\n");
    exit (EXIT_FAILURE);
  }
  memset (dst_mac, 0, 6);

  tmp = (unsigned char *) malloc (IP_MAXPACKET * sizeof (unsigned char));
  if (tmp != NULL) {
    ether_frame = tmp;
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array 'ether_frame'.\n");
    exit (EXIT_FAILURE);
  }
  memset (ether_frame, 0, IP_MAXPACKET);

  tmp = (char *) malloc (40 * sizeof (char));
  if (tmp != NULL) {
    interface = tmp;
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array 'interface'.\n");
    exit (EXIT_FAILURE);
  }
  memset (interface, 0, 40);

  tmp = (char *) malloc (40 * sizeof (char));
  if (tmp != NULL) {
    target = tmp;
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array 'target'.\n");
    exit (EXIT_FAILURE);
  }
  memset (target, 0, 40);

  tmp = (char *) malloc (16 * sizeof (char));
  if (tmp != NULL) {
    src_ip = tmp;
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array 'src_ip'.\n");
    exit (EXIT_FAILURE);
  }
  memset (src_ip, 0, 16);

// Interface to send packet through.
  strcpy (interface, "eth0");

// Submit request for a socket descriptor to lookup interface.
  if ((sd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
    perror ("socket() failed to get socket descriptor for using ioctl() ");
    exit (EXIT_FAILURE);
  }

// Use ioctl() to lookup interface and get MAC address.
  memset (&ifr, 0, sizeof (ifr));
  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
  if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
    perror ("ioctl() failed to get source MAC address ");
    return (EXIT_FAILURE);
  }
  close (sd);

// Copy source MAC address.
  memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6);

// Report source MAC address to stdout.
  printf ("MAC address for interface %s is ", interface);
  for (i=0; i<5; i++) {
    printf ("%02x:", src_mac[i]);
  }
  printf ("%02x\n", src_mac[5]);

// Resolve interface index.
  if ((device.sll_ifindex = if_nametoindex (interface)) == 0) {
    perror ("if_nametoindex() failed to obtain interface index ");
    exit (EXIT_FAILURE);
  }
  printf ("Index for interface %s is %i\n", interface, device.sll_ifindex);

// Set destination MAC address: broadcast address
  memset (dst_mac, 0xff, 6);

// Source IPv4 address:  you need to fill these out
  strcpy (src_ip, "192.168.128.9");

// Destination URL or IPv4 address (must be a link-local node)
  strcpy (target, "192.168.128.2");

// Fill out hints for getaddrinfo().
  memset (&hints, 0, sizeof (struct addrinfo));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = hints.ai_flags | AI_CANONNAME;

// Resolve source using getaddrinfo().
  if ((status = getaddrinfo (src_ip, NULL, &hints, &res)) != 0) {
    fprintf (stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
    exit (EXIT_FAILURE);
  }
  ipv4 = (struct sockaddr_in *) res->ai_addr;
  memcpy (&arphdr.sender_ip, &ipv4->sin_addr, 4);
  freeaddrinfo (res);

// Resolve target using getaddrinfo().
  if ((status = getaddrinfo (target, NULL, &hints, &res)) != 0) {
    fprintf (stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
    exit (EXIT_FAILURE);
  }
  ipv4 = (struct sockaddr_in *) res->ai_addr;
  memcpy (&arphdr.target_ip, &ipv4->sin_addr, 4);
  freeaddrinfo (res);

// Fill out sockaddr_ll.
  device.sll_family = AF_PACKET;
  memcpy (device.sll_addr, src_mac, 6);
  device.sll_halen = htons (6);

// ARP header

// Hardware type (16 bits): 1 for ethernet
  arphdr.htype = htons (1);

// Protocol type (16 bits): 2048 for IP
  arphdr.ptype = htons (ETH_P_IP);

// Hardware address length (8 bits): 6 bytes for MAC address
  arphdr.hlen = 6;

// Protocol address length (8 bits): 4 bytes for IPv4 address
  arphdr.plen = 4;

// OpCode: 1 for ARP request
  arphdr.opcode = htons (ARPOP_REQUEST);

// Sender hardware address (48 bits): MAC address
  memcpy (&arphdr.sender_mac, src_mac, 6);

// Sender protocol address (32 bits)
// See getaddrinfo() resolution of src_ip.

// Target hardware address (48 bits): zero, since we don't know it yet.
  memset (&arphdr.target_mac, 0, 6);

// Target protocol address (32 bits)
// See getaddrinfo() resolution of target.

// Fill out ethernet frame header.

// Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (ARP header)
  frame_length = 6 + 6 + 2 + ARP_HDRLEN;

// Destination and Source MAC addresses
  memcpy (ether_frame, dst_mac, 6);
  memcpy (ether_frame + 6, src_mac, 6);

// Next is ethernet type code (ETH_P_ARP for ARP).
// http://www.iana.org/assignments/ethernet-numbers
  ether_frame[12] = ETH_P_ARP / 256;
  ether_frame[13] = ETH_P_ARP % 256;

// Next is ethernet frame data (ARP header).

// ARP header
  memcpy (ether_frame + 14, &arphdr, ARP_HDRLEN);

// Submit request for a raw socket descriptor.
  if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
    perror ("socket() failed ");
    exit (EXIT_FAILURE);
  }

// Send ethernet frame to socket.
  if ((bytes = sendto (sd, ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
    perror ("sendto() failed");
    exit (EXIT_FAILURE);
  }

// Close socket descriptor.
  close (sd);

// Free allocated memory.
  free (src_mac);
  free (dst_mac);
  free (ether_frame);
  free (interface);
  free (target);
  free (src_ip);

  return (EXIT_SUCCESS);
}
