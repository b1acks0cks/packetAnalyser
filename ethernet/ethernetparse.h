#ifndef ETHERNET_HEADERS_H
#define ETHERNET_HEADERS_H

#include <stdio.h>
#include <pcap.h>


// Objective: parse the binary to ethernet_header
#define ETHERNET_MAC_AND_ETHER_SIZE 14

struct ethernet_header {
    char *destinationMac; // destination mac address
    char *sourceMac; // source mac address
    char *ethertype; //ethertype parsed to string
    char* eightq_tci; // optional 801.2q
    unsigned char *payload; // everything we have so far except the last 12 bits
    unsigned char *fcs;
};


//frees ethernet header that was intialised with heap memory exclusively
void free_eth(struct ethernet_header *head);
const char * get_ethertype(unsigned int ethertype);



// parses ethernet address from a given packet into ethernet_headers struct ( must free )
struct ethernet_header* parseFrame(const u_char* rawPacket, int packetLength);


#endif