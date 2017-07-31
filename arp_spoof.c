#define ETHER_ADDR_LEN	6
#define SIZE_ETHERNET	14
#define INET_ADDRSTRLEN	16
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <string.h> 
#include <stdio.h>
struct sniff_ethernet {

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

struct sniff_ip {
	uint8_t ip_vhl;		/* version << 4 | header length >> 2 */
	uint8_t ip_tos;		/* type of service */
	uint16_t ip_len;		/* total length */
	uint16_t ip_id;		/* identification */
	uint16_t ip_off;		/* fragment offset field */
	#define IP_RF 0x8000		/* reserved fragment flag */
	#define IP_DF 0x4000		/* dont fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	uint8_t ip_ttl;		/* time to live */
	uint8_t ip_p;		/* protocol */
	uint16_t ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)	(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)	(((ip)->ip_vhl) >> 4)

struct sockaddr_in source,dest;


int main(int argc, char *argv[])
{
		pcap_t *handle;			/* Session handle */
		char *dev;			/* The device to sniff on */
		char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
		struct bpf_program fp;		/* The compiled filter */
		char filter_exp[] = "port 80";	/* The filter expression */
		bpf_u_int32 mask;		/* Our netmask */
		bpf_u_int32 net;		/* Our IP */
		struct pcap_pkthdr *header;	/* The header that pcap gives us */
		const u_char *Buffer;		/* The actual packet */
		int size;
		int packetnumber = 10;
		u_char *buffer;
		int res;
		int i;
/* Define the device */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			return(2);
		}
		/* Find the properties for the device */
		if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
			fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
			net = 0;
			mask = 0;
		}
		/* Open the session in promiscuous mode */
		handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
		//handle = pcap_open_live("dum0", BUFSIZ, 1, 1000, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
			return(2);
		}
		/* Compile and apply the filter */
		if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return(2);
		}
		if (pcap_setfilter(handle, &fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return(2);
		}
	
	struct sniff_ethernet* ethernet;
	struct sniff_arp* arp;

	u_char packet[42];
	packet[0]=255;
    packet[1]=255;
    packet[2]=255;
    packet[3]=255;
    packet[4]=255;
    packet[5]=255;
    
    /* set mac source tomy mac */
    packet[6]=0x00;
    packet[7]=0x0b;
    packet[8]=0xdb;
    packet[9]=0xdd;
    packet[10]=0x3f;
    packet[11]=0xa1;
	// type = arp
	packet[12]=0x08;
	packet[13]=0x06;
	//data packet ************************************
	// hardware type =1 ethernet  (6 IEE 802)
	packet[14]=0x00;
	packet[15]=0x01;
	//protocol address type IPV4	
	packet[16]=0x08;
	packet[17]=0x00;
	//hardware address length = mac size
	packet[18]=0x06;
	// protocol address length = ipv4 length
	packet[19]=0x04;
	// opcode 1 = request , 2= reply
	packet[20]=0x00;
	packet[21]=0x01;
	//my mac
	packet[22]=0x00;
	packet[23]=0x0b;
	packet[24]=0xdb;
	packet[25]=0x5e;
	packet[26]=0x3f;
	packet[27]=0xa1;
	//my ip
	packet[28]=200;
	packet[29]=100;
	packet[30]=100;
	packet[31]=2;
	//packet[28]=argv[0];
	//packet[29]=argv[1];
	//packet[30]=argv[2];
	//packet[31]=argv[3];
	//dest mac 
	packet[32]=0;
	packet[33]=0;
	packet[34]=0;
	packet[35]=0;
	packet[36]=0;
	packet[37]=0;
	//dest ip
	packet[38]=81;
	packet[39]=31;
	packet[40]=164;
	packet[41]=123;

    
    /* Fill the rest of the packet */
   
	/*for(i=42;i<100;i++)
	{
        packet[i]=0;
    }*/
	for(i=0;i<5;i++)
	{


	    /* Send down the packet */
	    pcap_sendpacket(handle,packet,60);

	//pcap_sendqueue_transmit(outp, squeue, sync);
	}
	return 0;
}