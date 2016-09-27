#include <stdio.h>
#include <libnet.h>
#include <unistd.h>

void print_dotip4(u_int32_t ipaddr){
	unsigned char octet[4];
	for (int i=0; i<4; i++){
		octet[i] = (ipaddr >> (8*i)) & 0xFF;
	}
	printf("%d.%d.%d.%d\n", octet[3], octet[2], octet[1], octet[0]);
}

int main(int argc, char *argv[]){

	u_int32_t my_ip, gateway_ip, victim_ip;
	libnet_t *l;
	libnet_ptag_t t;
	char dev[] = "eth0";
	u_int8_t *packet;
	u_int32_t *packet_len;
	
	char errbuf[LIBNET_ERRBUF_SIZE];
	libnet_ether_addr* my_mac, gateway_mac, victim_mac;
	
	u_char broadcast[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	
	//check sudo or not
	if (geteuid() != 0) {
		fprintf(stderr, "err: you must be root to run this\n");
		return -1;
	}

	//initialize
	l = libnet_init(LIBNET_LINK_ADV, dev, errbuf);

	if(l==NULL){
		fprintf(stderr, "%s", errbuf);
		return 2;
	}
	else{
		//get ip address
		my_ip = libnet_get_ipaddr4(l);
	}
	printf ("Your IP address is ");
	print_dotip4(my_ip);


	return 0;
}
