#ifndef LINUX_COOKED_CAPTURES_HEADERS_H
#define LINUX_COOKED_CAPTURES_HEADERS_H

#include<stdint.h>
typedef unsigned char u_char;


typedef struct linux_cooked_capture {
    uint16_t packet_type;  // PACKET_HOST, PACKET_OUTGOING, etc.
    uint16_t hw_type;      // ARPHRD_ETHER, etc.
    uint16_t addr_len;     // length of link-layer address
    uint8_t  addr[8];      // link-layer address why the fuck would you store it like this bro????
    uint16_t protocol;     // EtherType (0x0800 = IPv4, 0x0806 = ARP, etc.)
    u_char* payload;
    int payload_size;
} linux_cooked_capture;

linux_cooked_capture* parse_sll(const u_char *pkt, int size);
void free_lnx_ckd_cptr(linux_cooked_capture* capture);
void test_linux_cooked_capture();

#endif