#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include "packet.h"

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}



int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }


  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  struct E_header eh;
  struct IP_header ih;
  struct TCP_header th;

  while (true) {
    struct pcap_pkthdr* header;
    //header: time, length of packet
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    //real packet is here
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("%u bytes captured\n", header->caplen);

    for(int i=0; i<6; i++){
       eh.dMac[i] = *packet++; // 0~5
    }
    printf("Destination MAC: %x:%x:%x:%x:%x:%x\n", eh.dMac[0], eh.dMac[1], eh.dMac[2], eh.dMac[3], eh.dMac[4], eh.dMac[5]);

    for(int i=0; i<6; i++){
       eh.sMac[i] = *packet++;
    }
    printf("Source MAC: %x:%x:%x:%x:%x:%x\n", eh.sMac[0], eh.sMac[1], eh.sMac[2], eh.sMac[3], eh.sMac[4], eh.sMac[5]);

    for(int i=0; i<2; i++){
       eh.etherType[i] = *packet++; //12~13
    }
    printf("EtherType: ");
    for(int i=0; i<2; i++){
       printf("%02x", eh.etherType[i]);
    }
    printf("\n");

    //printf("PPPPPPP: [0]%d [1]%d\n\n", eh.etherType[0], eh.etherType[1]);
    //IPv4

    if((eh.etherType[0] == 8) && (eh.etherType[1] == 0)){
        uint8_t ip_len[2];
        ip_len[0] = packet[2];
        ip_len[1] = packet[3];

        printf("IP_len: %d\n",(ip_len[0]<<8 | ip_len[1]));


        printf("Porotol Type: ");
        ih.Proto = packet[9];
        printf("%x\n", ih.Proto);

        for (int i=0; i<2; i++){
            *packet++;
        }

       for (int i=0; i<10; i++){
           *packet++;
       }
        //IP
        for(int i=0; i<4; i++){
            ih.sIP[i] = *packet++;
        }
        printf("Source IP: %d.%d.%d.%d\n", ih.sIP[0], ih.sIP[1], ih.sIP[2], ih.sIP[3]);
        for(int i=0; i<4; i++){
            ih.dIP[i] = *packet++;
        }
        printf("Destination IP: %d.%d.%d.%d\n", ih.dIP[0], ih.dIP[1], ih.dIP[2], ih.dIP[3]);

        //PORT
        if(ih.Proto == 6){
            for(int i=0; i<2; i++){
                th.sPort[i] = *packet++;
            }
            printf("SPORT: %d\n", (th.sPort[0]<<8 | th.sPort[1]));
            for(int i=0; i<2; i++){
                th.dPort[i] = *packet++;
            }
            printf("DPORT: %d\n", (th.dPort[0]<<8 | th.dPort[1]));
            for(int i=0; i<9; i++){
                *packet++;
            }
            //tcp segement length
            uint8_t tcp_payload;
            tcp_payload = *packet++;
            printf("payload length: %d\n", tcp_payload);
            for(int i=0; i<6; i++){
                *packet++;
            }
            for (int i=0; i<10; i++){
                printf("%0x", packet[i]);
            }
        }


        printf("\n");


        //ARP
    } else if ((eh.etherType[0] == 8) && (eh.etherType[1] == 6)) {
        for (int i=0; i<14; i++){
            *packet++;
        }
        for(int i=0; i<4; i++){
            ih.sIP[i] = *packet++;
        }
        for (int i=0; i<6; i++){
            *packet++;
        }
        printf("Source IP: %d.%d.%d.%d\n", ih.sIP[0], ih.sIP[1], ih.sIP[2], ih.sIP[3]);
        for(int i=0; i<4; i++){
            ih.dIP[i] = *packet++;
        }
        printf("Destination IP: %d.%d.%d.%d\n", ih.dIP[0], ih.dIP[1], ih.dIP[2], ih.dIP[3]);

    } else {
        // 86DD (IPv6)
        printf("Porotol Type: ");
        ih.Proto = packet[6];
        printf("%x\n", ih.Proto);
        //*packet++; *packet++;
        for(int i=0; i<8; i++){
            *packet++;
        }
        //IP
        for(int i=0; i<16; i++){
            ih.sIP[i] = *packet++;
        }
        printf("Source IP: %d%d::%d%d:%d%d:%d%d:%d%d:%d%d:%d%d:%d%d\n", ih.sIP[0], ih.sIP[1], ih.sIP[2], ih.sIP[3], ih.sIP[4],  ih.sIP[5], ih.sIP[6], ih.sIP[7], ih.sIP[8], ih.sIP[9], ih.sIP[10], ih.sIP[11], ih.sIP[12], ih.sIP[13], ih.sIP[14], ih.sIP[15]);
        for(int i=0; i<16; i++){
            ih.dIP[i] = *packet++;
        }
        printf("Destination IP: %d%d::%d%d:%d%d:%d%d:%d%d:%d%d:%d%d:%d%d\n", ih.dIP[0], ih.dIP[1], ih.dIP[2], ih.dIP[3], ih.dIP[4],  ih.dIP[5], ih.dIP[6], ih.dIP[7], ih.dIP[8], ih.dIP[9], ih.dIP[10], ih.dIP[11], ih.dIP[12], ih.dIP[13], ih.dIP[14], ih.dIP[15]);

        if(ih.Proto == 6){
            for(int i=0; i<2; i++){
                th.sPort[i] = *packet++;
            }
            printf("SPORT: %u\n", (th.sPort[0]<<8 | th.sPort[1]));
            for(int i=0; i<2; i++){
                th.dPort[i] = *packet++;
            }
            printf("DPORT: %u\n", (th.dPort[0]<<8 | th.dPort[1]));
        }

    }
    printf("\n");
  }

  pcap_close(handle);
  return 0;
}
