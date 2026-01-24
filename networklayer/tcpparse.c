#include<stdlib.h>
#include<pcap.h>

#include "tcpparse.h"
#include "ethernetparse.h"
#include "ipv4.h"
#include "ipv6.h"
#include "ipv4parse.h"
#include "ipv6parse.h"
#include "string.h"
#include "getflags.h"

#define PORT_SIZE 2
#define SEQ_NUM_SIZE 4
#define ACK_NUM_SIZE 4

typedef unsigned char u_char;

void free_tcp_headers(struct TCP_HEADERS* segment) {
    free(segment->flags);
    free(segment->options);
    free(segment->payload);
    free_tcp_flags(segment->flags);
    free(segment);
}


struct TCP_HEADERS* parseSegment(const u_char* packet, int size){
    struct TCP_HEADERS* result_segment = malloc( sizeof(struct TCP_HEADERS) );
    result_segment->source_port = 0;
    result_segment->dest_port = 0;
    result_segment->seq_num = 0;
    result_segment->ack_num = 0;
    result_segment->data_offset = 0;
    result_segment->flags = NULL;
    result_segment->window = 0;
    result_segment->checksum = 0;
    result_segment->urg_ptr = 0;
    result_segment->options = NULL;

    struct ethernet_header* frame = parseFrame(packet, size);
    if ( !strcmp("Internet Protocol version 4 (IPv4)", frame->ethertype) )
    {
        u_char currentbyte;
        u_char nextbyte;
        int currentposition;

        struct INET_V4_HEADERS* Packet = parsePacket(packet, size);
        
        currentposition = 0;
        currentbyte = (Packet->payload)[currentposition];
        nextbyte = (Packet->payload)[currentposition + 1];

        int source_port_bits = (currentbyte << 8) | nextbyte;
        result_segment->source_port = source_port_bits;
        
        currentposition += PORT_SIZE;
        currentbyte = (Packet->payload)[currentposition];
        nextbyte = (Packet->payload)[currentposition + 1];

        int dest_bits = (currentbyte << 8) | nextbyte;
        result_segment->dest_port = dest_bits;

        currentposition += PORT_SIZE;
        currentbyte = (Packet->payload)[currentposition];
        nextbyte = (Packet->payload)[currentposition + 1];

        unsigned int sequence_number_bits = (Packet->payload)[currentposition] << 24 | 
        (Packet->payload)[currentposition + 1] << 16 | 
        (Packet->payload)[currentposition + 2] << 8 | 
        (Packet->payload)[currentposition + 3];

        result_segment->seq_num = sequence_number_bits;

        currentposition += SEQ_NUM_SIZE;
        currentbyte = (Packet->payload)[currentposition];
        nextbyte = (Packet->payload)[currentposition + 1];

        unsigned int ack_number_bits = (Packet->payload)[currentposition] << 24 | 
        (Packet->payload)[currentposition + 1] << 16 | 
        (Packet->payload)[currentposition + 2] << 8 | 
        (Packet->payload)[currentposition + 3];

        result_segment->ack_num = ack_number_bits;
        
        currentposition += ACK_NUM_SIZE;
        currentbyte = (Packet->payload)[currentposition];
        nextbyte = (Packet->payload)[currentposition + 1];

        uint8_t data_offset_bits;
        data_offset_bits = (currentbyte & 0xF0) >> 4;
        result_segment->data_offset = data_offset_bits;

        currentposition += 1;
        currentbyte = (Packet->payload)[currentposition];
        nextbyte = (Packet->payload)[currentposition + 1];

        uint8_t flag_byte;
        flag_byte = currentbyte;

        char** flag_buffer = get_tcp_flags(currentbyte);
        result_segment->flags = flag_buffer;

        currentposition += 1;
        currentbyte = (Packet->payload)[currentposition];
        nextbyte = (Packet->payload)[currentposition + 1];

        uint16_t window_bits = (currentbyte << 8) | nextbyte;
        result_segment->window = window_bits;

        currentposition += 2;
        currentbyte = (Packet->payload)[currentposition];
        nextbyte = (Packet->payload)[currentposition + 1];

        uint16_t checksum = (currentbyte << 8) | nextbyte;
        result_segment->checksum = checksum;

        currentposition += 2;
        currentbyte = (Packet->payload)[currentposition];
        nextbyte = (Packet->payload)[currentposition + 1];

        uint16_t urg_ptr_bits = (currentbyte << 8) | nextbyte;
        result_segment->urg_ptr = urg_ptr_bits;

        currentposition += 2;
        int options_size = result_segment->data_offset - 5; // in 32 bit words
        if (result_segment->data_offset > 5){
           
            u_char *options_buffer = malloc(options_size * 4);

            for(int i = 0; i < options_size * 4; i++){
                 options_buffer[i] = (Packet->payload)[currentposition + i];
            }

            currentposition += options_size*4;
        }
        
        int tcp_header_bytes = result_segment->data_offset * 4;
        int payload_size = size - tcp_header_bytes;
        u_char *payload_bytes = malloc(payload_size);
        
        for(int i = 0; i < payload_size; i++){
            payload_bytes[i] = (Packet->payload)[currentposition + i];
        }

        result_segment->payload = payload_bytes;
        result_segment->payload_length = payload_size;

    }
    else if ( !strcmp("Internet Protocol Version 6 (IPv6)", frame->ethertype))
    {
        struct INET_V6_HEADERS *Packet = parsev6Packet(packet, size);

        u_char currentbyte;
        u_char nextbyte;

        int currentposition = 0;
        currentbyte = (Packet->payload)[currentposition];
        nextbyte = (Packet->payload)[currentposition + 1];

        int source_port_bits = (currentbyte << 8) | nextbyte;
        result_segment->source_port = source_port_bits;
        
        currentposition += PORT_SIZE;
        currentbyte = (Packet->payload)[currentposition];
        nextbyte = (Packet->payload)[currentposition + 1];

        int dest_bits = (currentbyte << 8) | nextbyte;
        result_segment->dest_port = dest_bits;

        currentposition += PORT_SIZE;
        currentbyte = (Packet->payload)[currentposition];
        nextbyte = (Packet->payload)[currentposition + 1];

        unsigned int sequence_number_bits = (Packet->payload)[currentposition] << 24 | 
        (Packet->payload)[currentposition + 1] << 16 | 
        (Packet->payload)[currentposition + 2] << 8 | 
        (Packet->payload)[currentposition + 3];

        result_segment->seq_num = sequence_number_bits;

        currentposition += SEQ_NUM_SIZE;
        currentbyte = (Packet->payload)[currentposition];
        nextbyte = (Packet->payload)[currentposition + 1];

        unsigned int ack_number_bits = (Packet->payload)[currentposition] << 24 | 
        (Packet->payload)[currentposition + 1] << 16 | 
        (Packet->payload)[currentposition + 2] << 8 | 
        (Packet->payload)[currentposition + 3];

        result_segment->ack_num = ack_number_bits;
        
        currentposition += ACK_NUM_SIZE;
        currentbyte = (Packet->payload)[currentposition];
        nextbyte = (Packet->payload)[currentposition + 1];

        uint8_t data_offset_bits;
        data_offset_bits = (currentbyte & 0xF0) >> 4;
        result_segment->data_offset = data_offset_bits;

        currentposition += 1;
        currentbyte = (Packet->payload)[currentposition];
        nextbyte = (Packet->payload)[currentposition + 1];

        uint8_t flag_byte;
        flag_byte = currentbyte;

        char** flag_buffer = get_tcp_flags(currentbyte);
        result_segment->flags = flag_buffer;

        currentposition += 1;
        currentbyte = (Packet->payload)[currentposition];
        nextbyte = (Packet->payload)[currentposition + 1];

        uint16_t window_bits = (currentbyte << 8) | nextbyte;
        result_segment->window = window_bits;

        currentposition += 2;
        currentbyte = (Packet->payload)[currentposition];
        nextbyte = (Packet->payload)[currentposition + 1];

        uint16_t checksum = (currentbyte << 8) | nextbyte;
        result_segment->checksum = checksum;

        currentposition += 2;
        currentbyte = (Packet->payload)[currentposition];
        nextbyte = (Packet->payload)[currentposition + 1];

        uint16_t urg_ptr_bits = (currentbyte << 8) | nextbyte;
        result_segment->urg_ptr = urg_ptr_bits;

        currentposition += 2;
        int options_size = result_segment->data_offset - 5; // in 32 bit words
        if (result_segment->data_offset > 5){
           
            u_char *options_buffer = malloc(options_size * 4);

            for(int i = 0; i < options_size * 4; i++){
                 options_buffer[i] = (Packet->payload)[currentposition + i];
            }

            currentposition += options_size*4;
        }
        
        int tcp_header_bytes = result_segment->data_offset * 4;
        int payload_size = size - tcp_header_bytes;
        u_char *payload_bytes = malloc(payload_size);
        
        for(int i = 0; i < payload_size; i++){
            payload_bytes[i] = (Packet->payload)[currentposition + i];
        }

        result_segment->payload = payload_bytes;
        result_segment->payload_length = payload_size;
    }
    else
    {
        printf("Network layer protocol unsupported\n");
    }
    
    free_eth(frame);
    return result_segment;
};

void testSegment(){
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
    char filter_exp[] = "tcp";
    bpf_u_int32 net = 0;

    pcap_compile(interface, &fp, filter_exp, 0, net);

    pcap_setfilter(interface, &fp);
    while(1) {
    packet = pcap_next(interface, &header);

    struct TCP_HEADERS* segment = parseSegment(packet, header.caplen);
    printf("Source port: %d\n", segment->source_port);
    printf("Destination port: %d\n", segment->dest_port);
    printf("Sequence number: %d\n", segment->seq_num);
    printf("%d", (segment->flags == 0));
    printf("Acknowledgment number: %d\n", segment->ack_num);
    printf("Data offset: %d\n", segment->data_offset);
    printf("Flags: ");
    
    if (!(segment->flags==0)){
    for(int i = 0; i < 8; i++){
        printf("%s ", segment->flags[i]);
        }
    }
    printf("\n");
    printf("Window: %d\n", segment->window);
    printf("Checksum: %d\n", segment->checksum);
    printf("Urgent Pointer: %d\n", segment->urg_ptr);
    printf("Payload: ");

    int payload_size = segment->payload_length;
    
    if ( !(segment->payload==0))
    {
    for(int i = 0; i < payload_size; i++){
        if (!(i % 8)) {
            printf("\n");
        }
        printf("%02x " , segment->payload[i]);
    }
    }
    else 
    {
        printf("\n");
        printf("NULL\n\n");
    }
    printf("\n\n");
    };
}