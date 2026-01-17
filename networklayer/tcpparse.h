

#include<stdint.h>
#ifndef TCP_HEADERS_H
#define TCP_HEADERS_H

typedef unsigned char u_char;


struct TCP_HEADERS {
    uint16_t source_port;
    uint16_t dest_port;
    unsigned int seq_num;
    unsigned int ack_num;
    uint8_t data_offset;
    char** flags;
    uint16_t window;
    uint8_t checksum;
    uint16_t urg_ptr;
    char* options;
    u_char* payload;
    int payload_length;
};

void free_tcp_headers(struct TCP_HEADERS* segment);

void testSegment();

struct TCP_HEADERS* parseSegment(const u_char* packet, int size);


#endif