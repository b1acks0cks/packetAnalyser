#include "ethernet/ethernetparse.h"
#include "ipv4/ipv4parse.h"
#include "ipv6/ipv6parse.h"
#include "networklayer/udpparse.h"
#include "networklayer/tcpparse.h"
#include "networklayer/getflags.h"
#include "raw/readlivebytes.h"
#include "linuxcookedcaptures/linuxcookedparse.h"

#include <stdio.h>
#include<stdlib.h>
#include<string.h>
#include<stdbool.h>


// continue find a way to implemen interfaces
void printflag();
void printminiflag();

char* BytesToAscii(u_char* hex_in_bytes, size_t size){
    char* ascii_result = malloc(size + 1);
    if(!ascii_result){
        printf("Heap allocation failed\n");
        exit(1);
    }
    ascii_result[size] = '\0'; // for null termination

    for(int position = 0; position < size; position++)
        ascii_result[position] = (char)(hex_in_bytes[position]);

    return ascii_result;
}

int main(int argc, char*argv[] ){
    int interface_name_size = 50;
    int user_specified_filter_size = 100;
    char interface_name[interface_name_size];
    char user_specified_filter[user_specified_filter_size];
    bool filter_set = false;

    char* dev, errbuf[PCAP_ERRBUF_SIZE];

    pcap_if_t **devices = malloc(sizeof(pcap_if_t));

    pcap_findalldevs(devices, errbuf);

    char bpf_filter[] = "";

    if (devices == NULL){
        fprintf(stderr, "Malloc error");
        return(2);
    }
    
    // find interface and filter flags first
    for(int i = 0; i < argc; i++){
        char* currentflag = argv[i];
        // lists all interfaces
        if(!strcmp(currentflag, "--list-interfaces")){
            for(pcap_if_t *device=*devices ; device!=NULL ;device = device->next){
                printf("Interface: %s\n", device->name);
            }
	   return 1;
        }
        // modify interface name and filters for captures below
        if(!strcmp(currentflag, "-filter")){
            printf("Setting filter: %s", argv[i+1]);
            strncpy(user_specified_filter, argv[i+1], user_specified_filter_size);   
            filter_set = true;
        }
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
    
    // open the specified interface and load filter
    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t *interface = pcap_open_live(interface_name, 65535, 1, 1000, errbuff);
    if (interface == NULL){
        printf("Error opening interface: %s\n Terminating Program\n", errbuff);
        exit(1);
    }
    struct bpf_program fp;
    bpf_u_int32 net = 0;
    
    if(filter_set){
        char filter_exp[user_specified_filter_size];
        strncpy(filter_exp, user_specified_filter, user_specified_filter_size);

        pcap_compile(interface, &fp, filter_exp, 0, net);

        int filter_successful = pcap_setfilter(interface, &fp);

        if (filter_successful){
            printf("Could not set specified filter: %s\n Terminating Progam\n", user_specified_filter);
            exit(1);
        }
    }

    switch(pcap_datalink(interface)) // determine what interfaces we're working on 
    {   
        struct pcap_pkthdr header;
        case DLT_EN10MB:
            // do the normal stuff here
        printf("Ethernet 2 \n");
        const u_char* packet_bytes;
   
        for(int i = 0; i < argc; i++){
        char* currentflag = argv[i];

        
        if(!strcmp(currentflag, "raw")){
            printf("Starting capture of raw bytes\n");
            printflag();
            
            printf("\n\n");
            read_raw_live(interface_name); // assumes normal ethernet
            }
        
        if(!strcmp(currentflag, "complete")){
            printf("Starting fully parsed scan\n");
            printflag();
            printf("\n");
          
            // find a way to handle keyboard interrupts here
            while(1){
                packet_bytes = pcap_next(interface, &header);


                struct ethernet_header *frame = parseFrame(packet_bytes, header.caplen);
                printminiflag();
                printf("Frame %s > %s \nEthertype: %s\n", frame->sourceMac, frame->destinationMac, frame->ethertype);
                
                
                char transportlayertype[50];
                if(!strcmp(frame->ethertype,"Internet Protocol version 4 (IPv4)")){
                    struct INET_V4_HEADERS *packet = parsePacket(packet_bytes, header.caplen);
                    printf("Network layer: %s > %s\n", packet->s_addr, packet->d_addr);
                    strncpy(transportlayertype, packet->protocol, 50);
                    free_INET_V4_HEADERS(packet);
                }
                else if (!strcmp(frame->ethertype, "Internet Protocol Version 6 (IPv6)")){
                    printf("Network layer: Internet Protocol version 6 (IPv6)\n");
                    struct INET_V6_HEADERS *packet = parsev6Packet(packet_bytes, header.caplen);
                    strncpy(transportlayertype, packet->next_header, 50);
                    free_INET_V6_HEADERS(packet); // yes I know it's a magic number but to be frank I don't care.
                }
                else{
                    printf("Network layer protocol unsupported");
                    continue;
                }

                const u_char* application_payload;
                size_t payload_size;
                if(!strcmp(transportlayertype, "TCP")){
                    struct TCP_HEADERS *transport = parseSegment(packet_bytes, header.caplen);
                    application_payload = transport->payload;
                    payload_size = transport->payload_length;
                    printf("Transport layer: %d > %d\n Checksum: %02x", transport->source_port, transport->dest_port, transport->checksum);
                    
                }
                else if (!strcmp(transportlayertype, "UDP")){
                    struct UDP_HEADERS *transport = parseDatagram(packet_bytes, header.caplen);
                    application_payload = transport->payload;
                    payload_size = transport->payload_length;
                    printf("Transport layer: %d > %d (UDP) \n", transport->source_port, transport->dest_port);
                    }
                else {
                    printf("Transport layer protocol unsupported \n");
                    continue;
                }

           
                if (application_payload != NULL){
                printf("Payload: \n");
                    for(int i = 0; i < payload_size; i++){
                        if (i % 32 == 0){
                            printf("\n");
                        }
                        printf("%c", application_payload[i]);
                    }
                printf("\n\n");
                } 
            }
            }

            }
            break;
        case DLT_LINUX_SLL:
            // do linux cooked captures here
            printf("Parsing beyond the link-layer with linux cooked captures is currently unsupported\n");
            while(1){
            packet_bytes = pcap_next(interface, &header);
            struct linux_cooked_capture *linux_headers = parse_sll(packet_bytes, header.caplen);
            printf("Address of the place where the address is stored %p\n", linux_headers->addr);
            printf("Addr len %d\n", linux_headers->addr_len);
            printf("Hw_type %d\n", linux_headers->hw_type);
            printf("Protocol 0x%02x\n", linux_headers->protocol);
            // linux cooked capture protocol codes are ALMOST the same as ethernet2 ethertype. In almost all network environments, they should match 1 to 1
            const char* protocol =  get_ethertype(linux_headers->protocol);
            printf("Netowrk layer protocol: %s\n", protocol);
            
            printf("Payload: \n");
            for(int i = 0; i < linux_headers->payload_size; i++){
                if ( i % 8 == 0){
                    printf("\n");
                }
            
                printf("%02x ", linux_headers->payload[i]);
            }
            printf("\n\n");

            free_lnx_ckd_cptr(linux_headers);
            printf("\n");
            }
            break;
        default:
            printf("Unsupported link-layer protocol");
    };


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
