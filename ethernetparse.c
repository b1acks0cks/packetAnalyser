#include <stdio.h>
#include "readlivebytes.c"
#include <pcap.h>
#include "getethertype.c"

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
void free_eth(struct ethernet_header *head) {
    free(head->destinationMac);
    free(head->sourceMac);
    free(head->ethertype);
    free(head->eightq_tci);
    free(head->payload);
    free(head->fcs);
    free(head);
}



// parses ethernet address from a given packet into ethernet_headers struct ( must free )
struct ethernet_header* parseMacAddress(const u_char* rawPacket, int packetLength){
    struct ethernet_header *result_headers =  (struct ethernet_header*) malloc(sizeof( struct ethernet_header)) ;
    u_char dest_bytes[6];
    u_char source_bytes[6];


    int destinationBytesLength = 6;
    int sourceBytesLength = 6;
    int macAddrTotal = destinationBytesLength + sourceBytesLength;


    for(int i = 0; i < macAddrTotal; i++){
        if(i < destinationBytesLength)
        {
            dest_bytes[i] = rawPacket[i];
        }
        else
            source_bytes[i - 6] = rawPacket[i];
    }
    // parse the destination and source to human readddddddble text in the form of a char*

    int macAddrLen = 18; // 17 characters and null terminating charracter
    char destMacAddr[macAddrLen];
    char sourceMacAddr[macAddrLen];

    int destAttempt = 
    sprintf(destMacAddr, 
        "%02x:%02x:%02x:%02x:%02x:%02x",
        dest_bytes[0],dest_bytes[1],dest_bytes[2],dest_bytes[3],dest_bytes[4],dest_bytes[5]);

    int sourceAttempt = 
    sprintf(sourceMacAddr, 
        "%02x:%02x:%02x:%02x:%02x:%02x",
        source_bytes[0],source_bytes[1],source_bytes[2],source_bytes[3],source_bytes[4],source_bytes[5]);
    
    // use heap allocation 

    //destination mac address
    result_headers->destinationMac= malloc(macAddrLen);
    memcpy(result_headers->destinationMac , destMacAddr, macAddrLen);

    //source mac address
    result_headers->sourceMac= malloc(macAddrLen);
    memcpy(result_headers->sourceMac ,sourceMacAddr , macAddrLen);
    
    // if bytes [12:13] is tpid, set eightq tab

    u_char tpid[2];
    tpid[0] = rawPacket[12];
    tpid[1] = rawPacket[13];

    char tpid_string[10];

    sprintf(tpid_string, "0x%02x%02x", (unsigned int)tpid[0], (unsigned int)tpid[1]);

    int offset = 0;
    if(tpid_string == "0x8100"){
        result_headers ->eightq_tci = 1;
        int offset = 4; 
    }
    else
        result_headers->eightq_tci= NULL;

    int etype_posit = 12 + offset;

    // extract ethertype to string
    u_char ethertypeBytes[2];

    ethertypeBytes[0] = rawPacket[etype_posit];
    ethertypeBytes[1] = rawPacket[etype_posit + 1];
    u_int16_t etype_hex = (ethertypeBytes[0] << 8) | ethertypeBytes[1];


    int etypename_len = 50;
    char etype_string[50];
    strncpy(etype_string, get_ethertype(etype_hex), sizeof(etype_string) - 1);
    etype_string[sizeof(etype_string) - 1] = '\0';
    
    result_headers->ethertype = (char*)malloc(etypename_len);

    strncpy(result_headers->ethertype, etype_string, etypename_len -1);

    int length_offset = 0; // look at issue titled misparsing on other systems
    int payloadSize = packetLength - length_offset;

    char *payload_bytes = malloc(packetLength);
    for(int i = 0; i < payloadSize; i++){
        payload_bytes[i] = rawPacket[etype_posit + 2 + i];
    }

    result_headers->payload= payload_bytes;
    result_headers->fcs= NULL;
    

    return result_headers;
}

int main(void)
{

    // read a packet and parse the mac address to test;

    pcap_t *handle;
    char errbuff[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live("wlp3s0", 65535, 1, 1000, errbuff);

    int successCode = pcap_datalink(handle);

    if (successCode == -1)
    {
        printf("Could not commence link-layer-aware parsing on interface");
        return 1;
    }
    if(handle == NULL){
        printf("Error in loading interface: %s \n",errbuff);
        return 1;
    }
    // filter for http traffic
    struct bpf_program fp;
    char filter_exp[] = "tcp port 80";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1){
        fprintf(stderr, "Couldn't pass filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }
    if(pcap_setfilter(handle, &fp) == -1)
        fprintf(stderr, "Couldn't install filter %s: %s \n", filter_exp, pcap_geterr(handle));
    
    struct pcap_pkthdr header;
    const u_char *packet;

    do{
        int count = 1;
        printf("Packet number %d --------------------------------------------- \n", count);
        printf("Layer 2-------------------------------- \n");
        packet = pcap_next(handle, &header);
                    
        struct ethernet_header *ether = parseMacAddress(packet, header.len);
        printf("Packet length: %d \n", header.len);
        printf("Destination mac address: %s\n", ether->destinationMac);
        printf("Source mac address: %s \n", ether->sourceMac);
        printf("Ethertype: %s\n", ether->ethertype);
        printf("Payload: bytes: \n");
        for(int i = 0; i < (header.len); i++)
        {
            printf("%02x ", packet[i + ETHERNET_MAC_AND_ETHER_SIZE]);
        }
        free_eth(ether);
        printf("\n\n");
        count++;

    }while(1);

    return 0; 

}