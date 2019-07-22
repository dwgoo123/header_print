#ifndef PACKET_H
#define PACKET_H

#endif // PACKET_H
#include <stdint.h>

struct E_header{
    uint8_t dMac[6];
    uint8_t sMac[6];
    uint8_t etherType[2];
};

struct IP_header{
    uint8_t sIP[4];
    uint8_t dIP[4];
    uint8_t Proto;

};

struct TCP_header{
    uint8_t sPort[2];
    uint8_t dPort[2];
};

uint32_t ntohl(uint32_t n){
        return (((n & 0xff000000) >> 24) | ((n & 0x00ff0000) >> 8) | ((n & 0x0000ff00 << 8) | ((n & 0x000000ff) << 24)));
}

uint16_t ntohs(uint16_t n){
    return ((n >> 8) | (n << 8));
}

