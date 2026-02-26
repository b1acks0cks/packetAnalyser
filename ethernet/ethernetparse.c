#include <stdio.h>
#include <pcap.h>

#include <string.h>
#include <stdlib.h>

// Objective: parse the binary to ethernet_header
#define ETHERNET_MAC_AND_ETHER_SIZE 14
typedef unsigned char u_char;

const char * get_ethertype(unsigned int ethertype);

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
struct ethernet_header* parseFrame(const u_char* rawPacket, int packetLength){
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
        result_headers->eightq_tci = malloc(sizeof(char));
        *(result_headers->eightq_tci) = 1;
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


const char * get_ethertype(unsigned int ethertype){
    switch(ethertype){
            case 0x0800: return "Internet Protocol version 4 (IPv4)";
            case 0x0804: return "Chaosnet";
            case 0x0806: return "Address Resolution Protocol (ARP)";
            case 0x0842: return "Wake-on-LAN[8]";
            case 0x22EA: return "Stream Reservation Protocol";
            case 0x22F0: return "Audio Video Transport Protocol (AVTP)";
            case 0x22F3: return "IETF TRILL Protocol";
            case 0x6002: return "DEC MOP RC";
            case 0x6003: return "DECnet Phase IV, DNA Routing";
            case 0x6004: return "DEC LAT";
            case 0x8035: return "Reverse Address Resolution Protocol (RARP)";
            case 0x809B: return "AppleTalk (EtherTalk)";
            case 0x80D5: return "LLC PDU (in particular, IBM SNA), preceded by 2 bytes length and 1 byte padding[9]";
            case 0x80F3: return "AppleTalk Address Resolution Protocol (AARP)";
            case 0x8100: return "VLAN-tagged frame (IEEE 802.1Q) and Shortest Path Bridging IEEE 802.1aq with NNI compatibility[10]";
            case 0x8102: return "Simple Loop Prevention Protocol (SLPP)";
            case 0x8103: return "Virtual Link Aggregation Control Protocol (VLACP)";
            case 0x8137: return "IPX";
            case 0x8204: return "QNX Qnet";
            case 0x86DD: return "Internet Protocol Version 6 (IPv6)";
            case 0x8808: return "Ethernet flow control";
            case 0x8809: return "Ethernet Slow Protocols[11] such as the Link Aggregation Control Protocol (LACP)";
            case 0x8819: return "CobraNet";
            case 0x8847: return "MPLS unicast";
            case 0x8848: return "MPLS multicast";
            case 0x8863: return "PPPoE Discovery Stage";
            case 0x8864: return "PPPoE Session Stage";
            case 0x887B: return "HomePlug 1.0 MME";
            case 0x888E: return "EAP over LAN (IEEE 802.1X)";
            case 0x8892: return "PROFINET Protocol";
            case 0x889A: return "HyperSCSI (SCSI over Ethernet)";
            case 0x88A2: return "ATA over Ethernet";
            case 0x88A4: return "EtherCAT Protocol";
            case 0x88A8: return "Service VLAN tag identifier (S-Tag) on Q-in-Q tunnel";
            case 0x88AB: return "Ethernet Powerlink[citation needed]";
            case 0x88B8: return "GOOSE (Generic Object Oriented Substation event)";
            case 0x88B9: return "GSE (Generic Substation Events) Management Services";
        default: return "Unknown";
    }
}