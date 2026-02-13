#include "ethernet/ethernetparse.h"
#include "ipv4/ipv4parse.h"
#include "ipv6/ipv6parse.h"
#include "networklayer/udpparse.h"
#include "networklayer/tcpparse.h"
#include "networklayer/getflags.h"
#include "raw/readlivebytes.h"

#include <stdio.h>
#include<stdlib.h>
#include<string.h>


// continue find a way to implemen interfaces
void printflag();
void printminiflag();

int main(int argc, char*argv[] ){
    
    int interface_name_size = 50;
    char interface_name[interface_name_size];

    char* dev, errbuf[PCAP_ERRBUF_SIZE];

    pcap_if_t **devices = malloc(sizeof(pcap_if_t));

    pcap_findalldevs(devices, errbuf);

    char bpf_filter[] = "";

    if (devices == NULL){
        fprintf(stderr, "Malloc error");
        return(2);
    }
    
    // find interface flags first
    for(int i = 0; i < argc; i++){
        char* currentflag = argv[i];
        // lists all interfaces
        if(!strcmp(currentflag, "--list-interfaces")){
            for(pcap_if_t *device=*devices ; device!=NULL ;device = device->next){
                printf("Interface: %s\n", device->name);
            }
	   return 1;
        }
        // modify interface name for captures below
        if(!strcmp(currentflag, "-i")){
            if (argc <= 2){
                printf("No interface was given. Please provide one \n");
                return 1;
            }
            else
            {
                printf("Interface given: ");
                strncpy(interface_name, argv[i+1], interface_name_size);
                printf("%s\n", interface_name);
            }    
        }
    }
    free(devices); // we don't need list of every type of interface so we can exit now
    
    // open the specified interface
    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t *interface = pcap_open_live(interface_name, 65535, 1, 1000, errbuff);
    const u_char* packet_bytes;

    if (interface == NULL){
        printf("Error opening interface: %s\n Terminating Program\n", errbuff);
        exit(1);
    }
    for(int i = 0; i < argc; i++){
    char* currentflag = argv[i];

    if(!strcmp(currentflag, "raw")){
        printf("Starting capture of raw bytes\n");
        printflag();
        
        printf("\n\n");
        read_raw_live(interface_name);
        }
    
    if(!strcmp(currentflag, "complete")){
        printf("Starting fully parsed scan\n");
        printflag();
        printf("\n");
        struct pcap_pkthdr header;
        // find a way to handle keyboard interrupts here
        while(1){
            packet_bytes = pcap_next(interface, &header);


            struct ethernet_header *frame = parseFrame(packet_bytes, header.caplen);
            printf("Frame %s > %s \n", frame->sourceMac, frame->sourceMac);
            printminiflag();
            char transportlayertype[50];
            if( !strcmp(frame->ethertype, "Internet Protocol version 4 (IPv4)") ){
                
                printf("Network layer: Internet Protocol version 4 (IPv4)");
                struct INET_V4_HEADERS *packet = parsePacket(packet_bytes, header.caplen);
                strncpy(transportlayertype, packet->protocol, 50);
                free_INET_V4_HEADERS(packet);

            }
            else if (!strcmp(frame->ethertype, "Internet Protocol Version 6 (IPv6)")){
                printf("Network layer: Internet Protocol version 4 (IPv6)");
                struct INET_V6_HEADERS *packet = parsev6Packet(packet_bytes, header.caplen);
                strncpy(transportlayertype, packet->next_header, 50);
                free_INET_V6_HEADERS(packet); // yes I know it's a magic number but to be frank I don't care.
            }
            else{
                printf("Network layer protocol unsupported");
                continue;
            }

            if(!strcmp(transportlayertype, "TCP")){
                struct TCP_HEADERS *transport = parseSegment(packet_bytes, header.caplen);
                printf("We are in TCP!! \n");
            }
            else if (!strcmp(transportlayertype, "UDP")){
                struct UDP_HEADERS *transport = parseDatagram(packet_bytes, header.caplen);
                printf("We are in UDP \n");
                }
            else {
                printf("Transport layer protocol unsupported");
              
                continue;
            }
            
        }
        }

    }
        
    }   


void printflag() {
    for(int i = 0; i < 50; i++){
        printf("*");
    }
}
void printminiflag() {
    for(int i = 0; i < 10; i++){
        printf("*");
    }
    printf("\n");
}