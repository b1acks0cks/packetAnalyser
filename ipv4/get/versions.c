#include "versions.h"
#include<stdint.h>



static const char *ipv_versions[16] = {
    [0]  = "Internet Protocol, pre-v4",
    [1]  = "Unknown or unsupported IP version",
    [2]  = "Unknown or unsupported IP version",
    [3]  = "Unknown or unsupported IP version",
    [4]  = "Internet Protocol version 4 (IPv4)",
    [5]  = "Internet Stream Protocol (ST / ST-II)",
    [6]  = "Internet Protocol version 6 (IPv6)",
    [7]  = "TP/IX The Next Internet (IPv7)",
    [8]  = "P Internet Protocol (PIP)",
    [9]  = "TCP and UDP over Bigger Addresses (TUBA)",
    [10] = "Unknown or unsupported IP version",
    [11] = "Unknown or unsupported IP version",
    [12] = "Unknown or unsupported IP version",
    [13] = "Unknown or unsupported IP version",
    [14] = "Unknown or unsupported IP version",
    [15] = "Version field sentinel value"
};


const char* get_ip_version(int code){
    
    if(code < 16){
        return ipv_versions[code];
    }
    else
        return "Unsopported IP version";
    }
