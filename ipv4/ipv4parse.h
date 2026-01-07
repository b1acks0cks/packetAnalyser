#ifndef IPV4_PARSE_HEADERS_H
#define IPV4_PARSE_HEADERS_H

#include<stdint.h>
typedef unsigned char u_char;
struct INET_V4_HEADERS {
    char* version;
    u_int8_t ihl;
    char* dscp; 
    char* ecn;
    u_int16_t packetLength; 
    char **flags; 
    u_int16_t identification;
    uint16_t fragmentOffset;
    uint8_t ttl;
    char* protocol;
    u_int16_t checksum;
    char* s_addr;
    char* d_addr;
    u_char* options;
    short options_size;
    u_char* payload;

};

void free_INET_V4_HEADERS(struct INET_V4_HEADERS *packet);

struct INET_V4_HEADERS* parsePacket(const u_char* packet, int size);

int testPacket();

#endif