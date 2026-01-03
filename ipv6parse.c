#include "ethernetparse.c"
#include<stdlib.h>
#include<stdint.h>
#include<pcap.h>

#include<arpa/inet.h>

#include "ipv6/ipv6.h"

#define OCTET_SIZE 1

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

void free_INET_V6_HEADERS(struct INET_V6_HEADERS* header){
    free(header->version);
    free(header->diff_services);
    free(header->ecn);
    free(header->s_6_addr);
    free(header->d_6_addr);
};

struct INET_V6_HEADERS *parsev6Packet(const u_char* packet, int size){
    struct ethernet_header *frame = parseFrame(packet, size);
    struct INET_V6_HEADERS *result = malloc(sizeof(struct INET_V6_HEADERS));

     // parse here
    u_char currentByte;
    u_char nextByte;
    int currentposition = 0;

    currentByte = (frame->payload)[currentposition];

    int max_version_size = 40;
    result->version = malloc(max_version_size);
    uint8_t version_code;

    version_code = (currentByte & 0xF0) >> 4;

    strncpy(result->version, get_ip6_version(version_code), max_version_size);
    
    nextByte = (frame->payload)[currentposition + 1];

    u_char traffic_class_bytse= ( (currentByte & 0xF) << 4 ) | (nextByte >> 4);

    int diff_services_bytes = (traffic_class_bytse & 0xFC) >> 2; 

    int max_dscp_size = 40;
    result->diff_services = malloc(max_dscp_size);
    strncpy(result->diff_services, get_dscp_class(diff_services_bytes), max_dscp_size);


    int max_ecn_size = 40;
    uint8_t ecn_code = (traffic_class_bytse & 0x30) >> 4;

    result->ecn = malloc(max_ecn_size);
    strncpy(result->ecn, get_ecn(ecn_code) ,max_dscp_size);

    int flow_label_bytes = (nextByte & 0xF << 16) | ( (frame->payload)[2] << 8) | ( (frame->payload)[3] );

    result->flow_label = flow_label_bytes;

    currentposition += OCTET_SIZE * 4;

    currentByte = (frame->payload)[currentposition];
    nextByte = (frame->payload)[currentposition + 1];

    int payload_length_bits = (currentByte << 8) | nextByte;

    result->payload_length = payload_length_bits;

    int max_next_header_size = 20;
    int next_header_position = 6;
    uint8_t next_header_bits = (frame->payload)[next_header_position];
    result->next_header = malloc(max_next_header_size);
    strncpy(result->next_header, get_protocol_name(next_header_bits), max_next_header_size);

    result->hop_limit = (u_char)(frame->payload)[7];

    currentposition += OCTET_SIZE*4;
    int i6_addr_length = 16;

    u_char source_addr[i6_addr_length];
    u_char dest_addr[i6_addr_length];

    for(int i = 0; i < i6_addr_length; i++)
        source_addr[i] = (frame->payload)[currentposition + i];
    

    currentposition += OCTET_SIZE * 16;

    for(int i = 0; i < i6_addr_length; i++)
       dest_addr[i] = (frame->payload)[currentposition + i];

    int max_ipv6_string_size = 150;
    
    char *source_string = malloc(max_ipv6_string_size);
    if (inet_ntop(AF_INET6, source_addr,source_string,max_ipv6_string_size) == NULL)
        perror("NTOP ERROR TERMINATING PROGRAM\n");
    
    char *dest_string = malloc(max_ipv6_string_size);
    if (inet_ntop(AF_INET6, dest_addr, dest_string ,max_ipv6_string_size) == NULL)
        perror("NTOP ERROR TERMINATING PROGRAM\n");
    
    

    result->s_6_addr = source_string;
    result->d_6_addr = dest_string;

    currentposition += OCTET_SIZE * 16;
    
    result->payload = calloc(sizeof(u_char), result->payload_length);
    for(int i = 0; i < result->payload_length; i++){
        (result->payload)[i] = (frame->payload)[currentposition + i];
    }

    free(frame);
    return result;
}

int main(){
    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t *interface = pcap_open_live("wlp3s0", 65535, 1, 1000, errbuff);

    if (interface == NULL){
        printf("Error opening interface: %s\n Terminating Program\n", errbuf);
        return 1;
    }

    const u_char *packet;
    struct pcap_pkthdr header;

    // add filter
    struct bpf_program fp;
    char filter_exp[] = "ip6";
    bpf_u_int32 net = 0;

    pcap_compile(interface, &fp, filter_exp, 0, net);

    pcap_setfilter(interface, &fp);


    while(1){
        packet = pcap_next(interface, &header);

        struct INET_V6_HEADERS *test = parsev6Packet(packet, header.caplen);
        //test here
        printf("Version: %s\n",test->version);
        printf("DSCP: %s\n", test->diff_services);
        printf("ECN: %s\n", test->ecn);
        printf("Flow label: %d \n", test->flow_label);
        printf("Payload length: %d\n", test->payload_length);
        printf("Next header: %s\n", test->next_header);
        printf("Hop limit: %d\n", test->hop_limit);
        printf("Source address: %s\n", test->s_6_addr);
        printf("Destination address: %s\n\n", test->d_6_addr);
        
        //print payload
        printf("Payload: \n");
        for(int i = 0; i < test->payload_length; i++){
            if ((i % 8 ) == 0)
                printf("\n");
            printf("%02x ", test->payload[i]);
        }

        free(test);
        }
        return 0;
    }