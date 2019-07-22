all:pcap_test

pcap_test: main.o
	gcc -g -o pcap_test main.o -lpcap

main.o: packet.h main.cpp
	gcc -g -c -o main.o main.cpp

clean:
	rm -f pcap_test
