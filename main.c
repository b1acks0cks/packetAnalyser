#include "ethernet/ethernetparse.h"
#include "ipv4/ipv4parse.h"
#include "ipv6/ipv6parse.h"
#include "networklayer/udpparse.h"
#include "networklayer/tcpparse.h"
#include "networklayer/getflags.h"


#include <stdio.h>
#include<stdlib.h>
#include<string.h>


// continue find a way to implemen interfaces


int main(int argc, char*argv[] ){
    
    char* dev, errbuf[PCAP_ERRBUF_SIZE];

    pcap_if_t **devices = malloc(sizeof(pcap_if_t));

    pcap_findalldevs(devices, errbuf);

    char* interface_name = "any";
    char bpf_filter[] = "";

    if (devices == NULL){
        fprintf(stderr, "Malloc error");
        return(2);
    }
    
    for(int i = 0; i < argc; i++){
        char* currentflag = argv[i];
        // lists all interfaces
        if(!strcmp(currentflag, "--list-interfaces")){
            for(pcap_if_t *device=*devices ; device!=NULL ;device = device->next){
                printf("Interface: %s\n", device->name);
            }
        }
    }

    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t *interface = pcap_open_live(interface_name, 65535, 1, 1000, errbuff);

    if (interface == NULL){
        printf("Error opening interface: %s\n Terminating Program\n", errbuff);
        exit(1);
    }

    const u_char *packet;
    struct pcap_pkthdr header;

    // add filter
    struct bpf_program fp;
    char filter_exp[] = "";
    bpf_u_int32 net = 0;

    pcap_compile(interface, &fp, filter_exp, 0, net);
    
    

    free(devices);
    return 0;
}
