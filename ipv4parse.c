#include<stdio.h>
#include "ethernetparse.c"

#include "ipv4/dscpcodes.c"
#include "ipv4/flags.c"
#include "ipv4/versions.c"
#include "ipv4/ecn.c"
#include "ipv4/protocols.c"

#include<arpa/inet.h>
#include<pcap.h>

#include<stdlib.h>


// in bits
#define VERSION_SIZE 4
#define IHL_SIZE 4
#define DSCP_SIZE 6
#define ECN_SIZE 2
#define LENGTH_SIZE_HEADER 16
#define FRAGMENTS_SIZE 16
#define TTL_SIZE 8
#define PROTOCOL_SIZE 8
#define CHECKSUM_SIZE 16
#define IP_ADDR_SIZE 32
#define IDENTIFICATION_SIZE 16

#define SIZEOFBYTE 8

struct INET_V4_HEADERS {
    char* version;
    u_int8_t ihl;
    char* dscp; // use get_dscp class to get class
    char* ecn;
    u_int16_t packetLength; 
    char **flags; // use get_flags find the flag information
    u_int16_t identification;
    uint16_t fragmentOffset;
    uint8_t ttl;
    char* protocol;
    u_int16_t checksum;
    char* s_addr;
    char* d_addr;
    u_char* options;
    short options_size;
    u_char* payload;

};

void free_INET_V4_HEADERS(struct INET_V4_HEADERS *packet) {
    free(packet->version);
    free(packet->dscp);
    free_flags(packet->flags);
    free(packet->protocol);
    free(packet->s_addr);
    free(packet->d_addr);
    free(packet->options);
    free(packet);

}

struct INET_V4_HEADERS* parsePacket(const u_char* packet, int size){

    struct ethernet_header*frame = parseFrame(packet, size);
    struct INET_V4_HEADERS *result = malloc(sizeof(struct INET_V4_HEADERS));

    int currentposition = 0;
    u_char currentByte = (frame->payload)[currentposition];
    
    uint8_t version_bits = (currentByte >> 4);

    int max_length = 40;
    result->version = (char*) malloc(max_length);
    strncpy(result->version, get_ip_version(version_bits), max_length);

    currentposition += (VERSION_SIZE + IHL_SIZE)/8;
    
    result->ihl = (currentByte & 0x0F);

    currentByte = (frame->payload)[currentposition];
    uint8_t dscp_bits;
    uint8_t ecn_bits;

    dscp_bits = ( (currentByte >> 2) & 0x3F ) ;

    int max_dscp_size = 45;
    result->dscp = malloc(max_dscp_size);
    strncpy(result->dscp, get_dscp_class(dscp_bits), max_dscp_size);
    
    ecn_bits = (currentByte & 0x3);
    int max_ecn_size = 10;
    result->ecn = malloc(max_ecn_size);
    strncpy(result->ecn, get_ecn(ecn_bits), max_ecn_size);

    

    currentposition += (DSCP_SIZE + ECN_SIZE)/8;

    currentByte = (frame->payload)[currentposition];
    u_char nextByte = (frame->payload)[currentposition + 1];

    uint16_t length = ( (uint16_t)currentByte << SIZEOFBYTE) | nextByte;
    result->packetLength = length; 

    currentposition += (LENGTH_SIZE_HEADER / 8);

    currentByte = (frame->payload)[currentposition];
    nextByte = (frame->payload)[currentposition + 1];

    uint16_t id_bit = (currentByte << SIZEOFBYTE) | (nextByte);
    result->identification = id_bit;

    currentposition += (IDENTIFICATION_SIZE / 8);

    currentByte = (frame->payload)[currentposition];
    nextByte = (frame->payload)[currentposition + 1];

    uint8_t flag_bits = 0;
    flag_bits = (currentByte >> 5) & 0x7;
    result->flags = get_flags(flag_bits); 
    
    uint16_t fragment_offset_bits = 0;
    
    currentByte = (frame->payload)[currentposition];
    nextByte = (frame->payload)[  currentposition + 1  ];


    u_char left = (uint8_t) (  (currentByte ) & 0x1F );
    u_char right = (uint8_t) ( (nextByte) ) ;

    fragment_offset_bits = ((u_int16_t)left << 8 ) | (uint16_t)right;
    result->fragmentOffset = fragment_offset_bits;


    currentposition += (FRAGMENTS_SIZE / 8);

    currentByte = (frame->payload)[currentposition];
    uint8_t TTL = (uint8_t)currentByte;
    result->ttl = TTL;

    currentposition += (TTL_SIZE/8) ; 
    currentByte = (frame->payload)[currentposition];

    result->protocol = get_protocol_name(currentByte);
    currentposition += (PROTOCOL_SIZE/8);
    currentByte = (frame->payload)[currentposition];
    nextByte = (frame->payload)[currentposition + 1];

    result->checksum = (currentByte<< 8) | nextByte;

    currentposition += (CHECKSUM_SIZE/8);
    currentByte = (frame->payload)[currentposition];
    nextByte = (frame->payload)[currentposition + 1];


    u_char ip_bytes_src[4] = {
        (frame->payload)[currentposition],
        (frame->payload)[currentposition + 1],
        (frame->payload)[currentposition + 2],
        (frame->payload)[currentposition + 3]
                        };
    
    int max_ip_length = 37;
    char* human_ip_src = malloc(max_ip_length);
    
    inet_ntop(AF_INET, ip_bytes_src, human_ip_src, 36);
    result->s_addr = human_ip_src;

    currentposition += (IP_ADDR_SIZE/8);
    currentByte = (frame->payload)[currentposition];
    nextByte = (frame->payload)[currentposition + 1];


    u_char ip_bytes_dest[4] = {
        (frame->payload)[currentposition],
        (frame->payload)[currentposition + 1],
        (frame->payload)[currentposition + 2],
        (frame->payload)[currentposition + 3]
                        };
    

    char* human_ip_dest = malloc(max_ip_length);
    
    inet_ntop(AF_INET, ip_bytes_dest, human_ip_dest, 36);

    result->d_addr = human_ip_dest;

    currentposition += (IP_ADDR_SIZE /8);

    // check if there are options. if their are then right it to a heap buffer
    int options_size = 0;
    if(result->ihl > 5){
        int max_options_size = 40;
        u_char *options_addr = calloc(max_options_size , sizeof(unsigned char));
        options_size = (result->ihl - 5)*4;

        for(int i = 0; i < options_size; i++)
            options_addr[i] = (frame->payload)[currentposition + i];
        
        result->options = options_addr;
    }
    else
    {
        result->options = NULL;
    }

    
    int payloadSize = size - (result->ihl * 4);
    u_char* payloadBits = malloc(payloadSize);

    currentposition += options_size;
    for(int i = 0; i < payloadSize; i++){
        payloadBits[i] = (frame->payload)[ (currentposition++)];
    }


    free(frame);
    return result; 
}



int testPacket(){
    
    char errormessage[PCAP_ERRBUF_SIZE];
    pcap_t *interface = pcap_open_live("wlp3s0", 65535, 1, 1000, errormessage);
    const u_char* packet;
    struct pcap_pkthdr header;


    // add filter
    struct bpf_program fp;
    char filter_exp[] = "";
    bpf_u_int32 net = 0;

    pcap_compile(interface, &fp, filter_exp, 0, net);

    pcap_setfilter(interface, &fp);

    if(interface == NULL)
    printf("Could not open a interface: %s", errormessage);


    packet = pcap_next(interface, &header);
    struct INET_V4_HEADERS *testPacket = parsePacket(packet, header.caplen);

    printf("Version: %s \n", testPacket->version);
    printf("IHL: %d \n", testPacket->ihl);
    printf("DSCP: %s \n", testPacket->dscp);
    printf("ECN: %s\n", testPacket->ecn);
    printf("Length: %d\n", testPacket->packetLength);
    printf("Identification: 0x%02x\n", testPacket->identification);
    printf("Flags: %s, %s, %s \n", testPacket->flags[0], testPacket->flags[1], testPacket->flags[2]);
    printf("Fragment Offset: %d \n", testPacket->fragmentOffset);
    printf("TTL: %d\n", testPacket->ttl);
    printf("Protocol: %s\n", testPacket->protocol);
    printf("Source addr: %s\n", testPacket->s_addr);
    printf("Destination addr: %s\n\n", testPacket->d_addr);
    printf("Options address: %p", testPacket);

    free_INET_V4_HEADERS(testPacket);
    return 0;


}

int main(void){
    testPacket();

}