#ifndef PACKET_STRUCTURE_H
#define PACKET_STRUCTURE_H

#endif // PACKET_STRUCTURE_H


#include <stdint.h>

typedef struct ethernet
{
    uint8_t d_mac[6];
    uint8_t s_mac[6];
    uint16_t type;
}Ethernet;

typedef struct ip
{
    uint8_t VHL;
    uint8_t TOS;
    uint16_t Total_LEN;
    uint32_t something;
    uint8_t TTL;
    uint8_t protocol;
    uint16_t checksum;
    uint8_t s_ip[4];
    uint8_t d_ip[4];
}Ip;

typedef struct tcp
{
    uint16_t s_port;
    uint16_t d_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t HLR;
    uint8_t something;
    uint16_t something2;
    uint32_t something3;
    uint8_t payload[10];
}Tcp;
