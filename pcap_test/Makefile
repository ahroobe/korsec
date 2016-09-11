#Makefile
all: pcap_test

pcap_test: pcap_test.o
	g++ -o pcap_test pcap_test.o -lpcap

pcap_test.o: pcap_test.cpp
	g++ -c -o pcap_test.o pcap_test.cpp

clean:
	rm -f pcap_test
	rm -f *.o
