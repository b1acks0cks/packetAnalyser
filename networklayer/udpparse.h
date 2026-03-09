#ifndef UDP_HEADERS_H
#define UDP_HEADERS_H
#include<stdint.h>

struct UDP_HEADERS {
    uint16_t source_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum;
    size_t payload_length;

    unsigned char *payload;
};

void testDatagram();
struct UDP_HEADERS *parseDatagram(const u_char* inputpacket, int size);

#endif