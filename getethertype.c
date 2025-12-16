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