#include "ethernetparse.c"
#include<stdlib.h>
#include<stdint.h>
#include<pcap.h>
#include "ipv6/ipv6.h"


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
    result->version = NULL;
    result->diff_services = NULL;
    result->ecn = NULL;
    result->flow_label = 0;
    result->payload_length = 0;
    result->next_header = NULL;
    result->hop_limit = 0;
    result->s_6_addr = NULL;
    result->d_6_addr = NULL;
   

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
    char filter_exp[] = "";
    bpf_u_int32 net = 0;

    pcap_compile(interface, &fp, filter_exp, 0, net);

    pcap_setfilter(interface, &fp);



    packet = pcap_next(interface, &header);

    struct INET_V6_HEADERS *test = parsev6Packet(packet, header.caplen);
    //test here

    
    free(test);
    return 0;
}