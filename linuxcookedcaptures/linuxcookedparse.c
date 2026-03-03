#include<stdlib.h>
#include<stdio.h>
#include<stdint.h>
#include<string.h>

#include <stdint.h>
#include <arpa/inet.h>  // for ntohs
#include<pcap.h>

#include"linuxcookedparse.h"


void free_lnx_ckd_cptr(linux_cooked_capture* capture){
    free(capture->payload);
    free(capture);
}



linux_cooked_capture* parse_sll(const u_char *pkt, int size) {
    //vibe coded
    linux_cooked_capture *h = malloc(sizeof(linux_cooked_capture));
    h->payload = malloc(size);
    if (!h) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }
    h->packet_type = ntohs(*(uint16_t *)(pkt + 0));
    h->hw_type     = ntohs(*(uint16_t *)(pkt + 2));
    h->addr_len    = ntohs(*(uint16_t *)(pkt + 4));
    memcpy(h->addr, pkt + 6, 8);
    h->protocol    = ntohs(*(uint16_t *)(pkt + 14));
    int i = 0;

    for(; i < size; i++){
        h->payload[i] = pkt[16 + i];
    }
    
    h->payload_size = i;
    return h;
}




void test_linux_cooked_capture(){
   char errormessage[PCAP_ERRBUF_SIZE];
    pcap_t *interface = pcap_open_live("any", 65535, 1, 1000, errormessage);
    if(!interface)
        printf("Could not open a interface: %s", errormessage);
    const u_char* packet;
    struct pcap_pkthdr header;
    if(!interface){
        printf("Could not open interface: %s", errormessage);
    }

    // add filter
    struct bpf_program fp;
    char filter_exp[] = "";
    bpf_u_int32 net = 0;

    pcap_compile(interface, &fp, filter_exp, 0, net);

    pcap_setfilter(interface, &fp);
    while(1) { 
        packet = pcap_next(interface, &header);
        linux_cooked_capture* goofy_header = parse_sll(packet, header.caplen);
        printf("Addr (first memory address): %p\n", goofy_header -> addr);
        printf("Addr length: %d\n", goofy_header ->addr_len);
        printf("Hw_types: %02x\n", goofy_header ->hw_type);
        printf("Protocol: %02x\n", goofy_header ->protocol);
        for(int i = 0; i < goofy_header->payload_size; i++){
            if(i % 8 == 0){
                printf("\n");
            }
            printf("%02x ", goofy_header->payload[i]);
        }
    }     

}