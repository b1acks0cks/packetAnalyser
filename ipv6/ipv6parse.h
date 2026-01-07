#ifndef IPV6_PARSE_HEADERS_H
#define IPV6_PARSE_HEADERS_H

#include<stdint.h>
typedef unsigned char u_char;
struct INET_V6_HEADERS {
    char* version;
    char* diff_services;
    char* ecn;
    int flow_label;
    uint16_t payload_length;
    char* next_header;
    uint8_t hop_limit;
    char* s_6_addr;
    char* d_6_addr;
    u_char* payload;
};

void free_INET_V6_HEADERS(struct INET_V6_HEADERS* header);

struct INET_V6_HEADERS *parsev6Packet(const u_char* packet, int size);

int testv6Packet();

#endif