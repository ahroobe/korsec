#include <pcap.h>
#include <stdio.h>
#include <unistd.h>
#include <libnet.h>

/*
1. which interface? : "eth0".
2. initialize pcap. what device? maybe can be multiple. SESSION
3. we must create rule. (pick protocol, port# ,,,)
   string. pcap can read.
4. execution loop. 
5. close session.
*/

/* callback function for each packet arriving*/
void callback(u_char *useless, const struct pcap_pkthdr* pkthdr, const u_char* packet){

	static int count = 1;

	/* ethernet,ip,tcp header */
	libnet_ethernet_hdr* eth_hdr;
	libnet_ipv4_hdr* ip_hdr;
	libnet_tcp_hdr* tcp_hdr;

	const u_char* payload;
	u_int ip_len;
	u_int tcp_len;
	u_int payload_len;
	u_int total_len;


	eth_hdr = (struct libnet_ethernet_hdr *) (packet);

	/* ip check*/
	if(ntohs(eth_hdr->ether_type) == ETHERTYPE_IP){
		/* get ip_hdr */
		ip_hdr = (struct libnet_ipv4_hdr *) (packet + sizeof(struct libnet_ethernet_hdr));
		ip_len = ip_hdr->ip_hl * 4;
		total_len = ntohs(ip_hdr->ip_len);

		/*tcp check*/
		if(ip_hdr->ip_p == IPPROTO_TCP){
			/*initialize tcp packet*/
			tcp_hdr = (struct libnet_tcp_hdr *) ((u_char*)ip_hdr + ip_len);
			tcp_len = (u_int)tcp_hdr->th_off * 4;

			/* print all data */
			printf("\nPacket number [%d], length of this packet is: %d\n", count++, pkthdr->len);

		        /* print data from ethernet header */
        		printf("Source MAC address : ");
			for (int i=0;i<6;i++){
				printf("%02X", eth_hdr->ether_shost[i]);
				if(i<5)
					printf(":");
			}
                        printf("\nDestination MAC address : ");
                        for (int i=0;i<6;i++){
                                printf("%02X", eth_hdr->ether_dhost[i]);
                                if(i<5)
                                        printf(":");
                        }

			/* print data from ip header */
			printf("\nSource IP address: %s\n", inet_ntoa(ip_hdr->ip_src));
			printf("Destination IP address: %s\n", inet_ntoa(ip_hdr->ip_dst));

			/* print data from tcp part */
			printf("Source port: %d\n", ntohs(tcp_hdr->th_sport));
			printf("Destination port: %d\n", ntohs(tcp_hdr->th_dport));

			/* payload of packet */
			payload = ((u_char*)tcp_hdr+tcp_len);	
			payload_len = total_len - ip_len - tcp_len;
			printf("length of payload : %d\n", payload_len);
			if(payload_len > 0){
				printf("payload: ");
				for(int i=0; i<payload_len;i++){
					if(isprint(*payload))
						printf("%c",*payload);
					else	
						printf(".");
					payload++;
				}
				printf("\n");
			}	
		}

	}
}
int main(int argc, char *argv[]){

	pcap_t *handle;
	char dev[] = "eth0";
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	struct pcap_pkthdr header;
	const u_char *packet;
	bpf_u_int32 mask;
	bpf_u_int32 net;
	char filter_exp[] = "";
	libnet_ethernet_hdr* eth_hdr;

	if (geteuid() != 0) {
		fprintf(stderr, "err: you must be root to run this\n");
		return -1;
	}
	/* define the device 
	I don't know why but can't use pcap_loopupdev


	dev = pcap_loopupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	*/
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
	if (pcap_compile(handle, &fp, argv[1], 0, net) == -1) {
		fprintf(stderr, "Coudln't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Coudln't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
	}

	/* Grap a packet */
	packet = pcap_next(handle, &header);
	/* loop for 100 times */
	pcap_loop(handle,100,callback, NULL);
	/* close the session */
	pcap_close(handle);

	return 0;
}
