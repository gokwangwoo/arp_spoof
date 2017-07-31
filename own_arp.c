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
		printf("no ip_address\n");
		close(fd);
		return 0;
	}
	 
	close(fd);
	
	sin = (struct sockaddr_in*) &ifr.ifr_addr;
	*ip = sin->sin_addr;

	return 1;
}

int main(int argc, char *argv[])
{
		pcap_t *handle;			/* Session handle */
		//char *dev;			/* The device to sniff on */
		char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
		struct bpf_program fp;		/* The compiled filter */
		bpf_u_int32 mask;		/* Our netmask */
		bpf_u_int32 net;		/* Our IP */
		char filter_exp[50] = "arp src host";
		struct pcap_pkthdr *header;	/* The header that pcap gives us */
		const u_char *Buffer;		/* The actual packet */
		int size;
		//int packetnumber = 10;
		u_char *buffer;
		int res;
		
		struct in_addr my_ip_addr;
		struct in_addr victim_ip_addr;
		struct in_addr target_ip_addr;
		char ip_addr[16];
		int length = 0;
		u_char my_mac[6];
		u_char victim_mac[6];
		int flag = 0;

		 u_char packet[100];
	pcap_if_t *alldevs;
    pcap_if_t *d;
    int i=0,j;
	int inum;
    char error[PCAP_ERRBUF_SIZE];
    pcap_t *inp,*outp;

    /* Retrieve the device list */
 if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	
	/* Print the list */
	for(d=alldevs; d; d=d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}
	
	if(i==0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}
	
	printf("Enter the interface number (1-%d):",i);
	scanf("%d", &inum);
	
	if(inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		//Free the device list//
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	/* //Jump to the selected adapter */
	for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
	
	/* //Open the device */
	/* //Open the adapter */
	

	if ((outp = pcap_open_live(d->name,	// name of the device
							 65536,			// portion of the packet to capture. 
											// 65536 grants that the whole packet will be captured on all the MACs.
							 1,				// promiscuous mode (nonzero means promiscuous)
							 1000,			// read timeout
							 errbuf			// error buffer
							 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		// Free the device list 
		pcap_freealldevs(alldevs);
		return -1;
	}
	if(argc < 4){
		printf("./send_arp interface_name victim_ip target_ip!!\n");
		return -1;	
	}
	
	//trncat(filter_exp, argv[2], strlen(argv[2]));

	
	
	/*broadcast */
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
   
	for(i=42;i<100;i++)
	{
        packet[i]=0;
    }
	for(i=0;i<5;i++)
	{


	    /* Send down the packet */
	    pcap_sendpacket(outp,packet,60);

	//pcap_sendqueue_transmit(outp, squeue, sync);
	}

		return 0;
}