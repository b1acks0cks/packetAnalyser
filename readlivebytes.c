
#include<pcap.h>
#include<stdio.h>
#include<stdlib.h>
#include<stdbool.h>
#include<string.h>


typedef unsigned char u_char;
pcap_t *handle;
char errbuf[PCAP_ERRBUF_SIZE];

// captures a single packet and returns the bytes of the captured packet as a uchar ( must be freed )
u_char* capture_single(){
    handle = pcap_open_live("wlp3s0", 65535, 1, 1000, errbuf);
    if(handle==NULL){
        printf("Could not open wlps30: %s \n", errbuf);
        perror("Terminating program \n");
    }

    int max_packet_size = 65535;
    u_char *copy = malloc((max_packet_size));
    struct pcap_pkthdr header;

    
    const u_char *packet;
    packet = pcap_next(handle, &header);

    memcpy(copy, packet, sizeof(header.caplen));
    return copy;
}

int readraw(){

    //pcap_open_live(interface name (char[]), snaplen(max bytes per packet), promiscuos mode, readtimeout in milliseconds, errorbuffer)
    

    handle = pcap_open_live("wlp3s0", 65535, 1, 1000, errbuf);
    if(handle==NULL){
        printf("Could not open wlps30: %s \n", errbuf);
        return 1;
    }

    struct pcap_pkthdr header;
    const u_char *packet;


    while(true){
        packet = pcap_next(handle, &header);


        printf("Captured a packet with length %u\n", header.len);
        printf("Raw bytes: \n");
        for(int i = 0; i < header.len; i++)
        {
            printf("%02x ", packet[i]);
        }
        printf("\n\n");
    }




    return 0;
}

/*

int main(){
    const u_char* packet;
    packet = capture_single();
    

    

    free((u_char*)packet);
    
    return 1;
}
*/