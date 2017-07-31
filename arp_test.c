#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#define ETHER_ADDR_LEN	6
#define SIZE_ETHERNET	14
#define INET_ADDRSTRLEN	16

struct ether_header {
	uint8_t h_dest[ETHER_ADDR_LEN]; /* Destination host address */
	uint8_t h_source[ETHER_ADDR_LEN]; /* Source host address */
	uint16_t h_proto; /* IP? ARP? RARP? etc */
};

struct sniff_arp {
   uint16_t arp_htype; /*hardware type*/
   uint16_t arp_p; /*protocol*/
   uint8_t arp_hsize; /*hardware size*/
   uint8_t arp_psize; /*protocol size*/
   uint16_t arp_opcode; /*opcode*/
   uint8_t arp_smhost[16]; /*sender mac address*/
   struct in_addr arp_sip; /*sender ip address*/
   uint8_t arp_dmhost[16]; /*target mac address*/
   struct in_addr arp_dip; /*target ip address*/
};
int main(int argc, char* argv[])
{
	struct sockaddr_ll sll;
}