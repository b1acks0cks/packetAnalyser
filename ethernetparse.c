#include<stdio.h>
#include "readlivebytes.c"
#include<pcap.h>

// Objective: parse the binary to ethernet_header

struct ethernet_header {
    char *destinationMac; // destination mac address
    char *sourceMac; // source mac address
    char* ethertype; //ethertype parsed to string
    char* eightq; // optional 801.2q
    unsigned char *payload; // everything we have so far except the last 12 bits
    unsigned char *fcs;
};


//frees ethernet header that was intialised with heap memory exclusively
void free_eth(struct ethernet_header *head) {
    free(head->destinationMac);
    free(head->sourceMac);
    free(head->ethertype);
    free(head->eightq);
    free(head->payload);
    free(head->fcs);
    free(head);
}

// parses ethernet address from a given packet into ethernet_headers struct ( must free )
struct ethernet_header* parseMacAddress(const u_char* rawPacket){
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
    
    // extract the next 16 bytes to see if it contains the TPID
    result_headers->ethertype= NULL;
    result_headers->payload= NULL;
    result_headers->eightq= NULL;
    result_headers->fcs= NULL;
    

    return result_headers;
}

int main(void)
{

    // read a packet and parse the mac address to test;

    pcap_t *handle;
    char errbuff[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live("wlp3s0", 65535, 1, 1000, errbuff);
    if(handle == NULL){
        printf("Error in loading interface: %s \n",errbuff);
        return 1;
    }
    
    
    struct pcap_pkthdr header;
    const u_char *packet;

    
    packet = pcap_next(handle, &header);
    


    struct ethernet_header *ether = parseMacAddress(packet);
    printf("Destination mac address: %s\n", ether->destinationMac);
    printf("Source mac address: %s \n", ether->sourceMac);
    free_eth(ether);

    return 0; 
}