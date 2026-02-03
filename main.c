#include "ethernet/ethernetparse.h"
#include "ipv4/ipv4parse.h"
#include "ipv6/ipv6parse.h"
#include "networklayer/udpparse.h"
#include "networklayer/tcpparse.h"
#include "networklayer/getflags.h"


#include <stdio.h>
#include<stdlib.h>


// find a way to read live bytes on a given intercace !!!
// find a way to read live bytes on a given intercace !!!
// find a way to read live bytes on a given intercace !!!
// find a way to read live bytes on a given intercace !!!
// find a way to read live bytes on a given intercace !!!
// find a way to read live bytes on a given intercace !!!
// find a way to read live bytes on a given intercace !!!
// find a way to read live bytes on a given intercace !!!
// find a way to read live bytes on a given intercace !!!
// find a way to read live bytes on a given intercace !!!
// find a way to read live bytes on a given intercace !!!
// find a way to read live bytes on a given intercace !!!
// find a way to read live bytes on a given intercace !!!




int main(int argc, char*argv[] ){
    
    char* dev, errbuf[PCAP_ERRBUF_SIZE];

    pcap_if_t **devices = malloc(sizeof(pcap_if_t));

    pcap_findalldevs(devices, errbuf);

    
    if (devices == NULL){
        fprintf(stderr, "Malloc error");
        return(2);
    }
    
    /*
    for(pcap_if_t *currentinterface = devices[0]; currentinterface != NULL; currentinterface = currentinterface->next){
        printf("Interfcace %s\n", currentinterface->name);
    }
    */
    
    for(int i = 0; i < argc; i++){
        printf("%s \n", argv[i]);
    }

    free(devices);
    return 0;
}