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

int main(int argc, char *argv[]){

	pcap_t *handle;
	char dev[] = "eth0";
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "port 23"; 	/* rules */
	bpf_u_int32 net;
	bpf_u_int32 mask;
	struct pcap_pkthdr header;
	const u_char *packet;

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
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Coudln't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Coudln't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
	}

	/* Grap a packet */
	packet = pcap_next(handle, &header);
	/* print length */
	printf("Jacked a packet with length of [%d]\n", header.len);
	/* close the session */
	pcap_close(handle);

	return 0;
}
