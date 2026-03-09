#include<stdio.h>
#include<stdint.h>
#include<pcap.h>
#include<stdlib.h>
#include<stdint.h>
#include<string.h>

#include "udpparse.h"
#include "ethernetparse.h"
#include "ipv4parse.h"
#include "ipv6parse.h"

#define BYTE_SIZE 8
#define PORT_SIZE 2

typedef unsigned char u_char;

struct UDP_HEADERS *parseDatagram(const u_char* inputpacket, int size){
    struct UDP_HEADERS *result = malloc(sizeof(struct UDP_HEADERS));
    result->source_port = 0;
    result->dest_port = 0;
    result->length = 0;
    result->checksum = 0;
    result->payload = NULL;

    struct ethernet_header *frame = parseFrame(inputpacket, size);
    if( !strcmp("Internet Protocol version 4 (IPv4)", frame->ethertype) ){
        struct INET_V4_HEADERS *network_packet = parsePacket(inputpacket, size);
        if( strcmp( network_packet->protocol, "UDP") == 0)
        {
            if(!network_packet->payload)
                perror("No packet");
            int payload_size_b = (network_packet->packetLength) - (network_packet->ihl)*4;
            int currentposition = 0;

            u_char currentByte;
            u_char nextByte;
            
            currentByte = (network_packet->payload)[currentposition];
            nextByte = (network_packet->payload)[currentposition + 1];

            uint16_t source_bits = (currentByte << BYTE_SIZE) | (nextByte);
            result->source_port = source_bits;

            currentposition += PORT_SIZE;

            currentByte = (network_packet->payload)[currentposition];
            nextByte = (network_packet->payload)[currentposition + 1];

            uint16_t destination_bits = (currentByte << BYTE_SIZE) | (nextByte);
            result->dest_port = destination_bits;
            
            currentposition += PORT_SIZE;
            currentByte = (network_packet->payload)[currentposition];
            nextByte = (network_packet->payload)[currentposition + 1];

            uint16_t length_bits = ( (currentByte << BYTE_SIZE) | nextByte);
            result->length = length_bits;

            currentposition += PORT_SIZE;
            currentByte = (network_packet->payload)[currentposition];
            nextByte = (network_packet->payload)[currentposition + 1];

            uint16_t checksum_bits = (currentByte << BYTE_SIZE) | nextByte;
            result->checksum = checksum_bits;   

            currentposition += PORT_SIZE;

            result->payload = malloc(result->length);
            int iteration = 0;
            for(; iteration < result->length; iteration++){
                *(result->payload + iteration) = *(network_packet->payload + iteration); // I used pointer arithmetic because I can
            }

            result->payload_length = (size_t)(iteration);
    }
    }
    else if ( !strcmp("Internet Protocol Version 6 (IPv6)", frame->ethertype)){
        struct INET_V6_HEADERS* network_packet = parsev6Packet(inputpacket, size);
            if(!network_packet->payload)
                perror("No packet");
            int payload_size_b = (network_packet->payload_length);
            int currentposition = 0;

            u_char currentByte;
            u_char nextByte;
            
            currentByte = (network_packet->payload)[currentposition];
            nextByte = (network_packet->payload)[currentposition + 1];

            uint16_t source_bits = (currentByte << BYTE_SIZE) | (nextByte);
            result->source_port = source_bits;

            currentposition += PORT_SIZE;

            currentByte = (network_packet->payload)[currentposition];
            nextByte = (network_packet->payload)[currentposition + 1];

            uint16_t destination_bits = (currentByte << BYTE_SIZE) | (nextByte);
            result->dest_port = destination_bits;
            
            currentposition += PORT_SIZE;
            currentByte = (network_packet->payload)[currentposition];
            nextByte = (network_packet->payload)[currentposition + 1];

            uint16_t length_bits = ( (currentByte << BYTE_SIZE) | nextByte);
            result->length = length_bits;

            currentposition += PORT_SIZE;
            currentByte = (network_packet->payload)[currentposition];
            nextByte = (network_packet->payload)[currentposition + 1];

            uint16_t checksum_bits = (currentByte << BYTE_SIZE) | nextByte;
            result->checksum = checksum_bits;   

            currentposition += PORT_SIZE;

            result->payload = malloc(result->length);

            int iteration = 0;
            for(; iteration < result->length; iteration++)
                *(result->payload + iteration) = *(network_packet->payload + iteration); // I used pointer arithmetic because I can
            
            result->payload_length = iteration;
    }
    else {
        printf("Unsupported network layer protocol");
    }
    
    // result->payload = malloc(result->length);
    free(frame);

    return result;
}

void free_datagram(struct UDP_HEADERS *datagram){
    free(datagram->payload);
    free(datagram);
}


void testDatagram(){
    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t *interface = pcap_open_live("wlp3s0", 65535, 1, 1000, errbuff);

    if (interface == NULL){
        printf("Error opening interface: %s\n Terminating Program\n", errbuff);
        exit(1);
    }

    const u_char *packet;
    struct pcap_pkthdr header;

    // add filter
    struct bpf_program fp;
    char filter_exp[] = "udp and ip6";
    bpf_u_int32 net = 0;

    pcap_compile(interface, &fp, filter_exp, 0, net);

    pcap_setfilter(interface, &fp);
    while(1){

        packet = pcap_next(interface, &header);

    
        struct UDP_HEADERS *datagram = parseDatagram(packet, header.caplen);
        printf("Source port: %d\n", datagram->source_port);
        printf("Destination port: %d\n", datagram->dest_port);
        printf("Length: %d\n", datagram->length);
        printf("Checksum: 0x%02x\n", datagram->checksum);
        printf("Payload: \n");
        for(int i = 0; i < datagram->length; i++){
            if((i % 8) == 0){
                printf("\n");
            }
            printf("%02x ", *(datagram->payload + i));
        }
        printf("\n\n");
        free_datagram(datagram);
    }
}