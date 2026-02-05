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


int main(int argc, char*argv[] ){
    
    char* dev, errbuf[PCAP_ERRBUF_SIZE];

    pcap_if_t **devices = malloc(sizeof(pcap_if_t));

    pcap_findalldevs(devices, errbuf);

    int interface_name_size = 50;
    char interface_name[interface_name_size];
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
                return 0;
            }
        }
        // modify interface name for captures below
        if(!strcmp(currentflag, "-i")){
            printf("Interface given: ");
            strncpy(interface_name, argv[i+1], interface_name_size);
            if (argc <= 2){
                printf("No interface was given. Please provide one \n");
                return 1;
            }
            else{
                printf("Interface given: ");
                printf("%s\n", interface_name);
            }
        }
    }
    free(devices); // we don't need list of every type of interface so we can exit now
    
    // open the specified interface
    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t *interface = pcap_open_live(interface_name, 65535, 1, 1000, errbuff);
    if (interface == NULL){
        printf("Error opening interface: %s\n Terminating Program\n", errbuff);
        exit(1);
    }
    for(int i = 0; i < argc; i++){
    char* currentflag = argv[i];

    printf("Currentflag: %s", currentflag);
    if(!strcmp(currentflag, "raw")){
        printf("Starting capture of raw bytes\n");
        for(int i = 0; i < 50; i++)
            printf("*");
        }
        printf("\n\n");
        read_raw_live(interface_name);
    }   


    return 0;
}
