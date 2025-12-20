#include<stdio.h>

const char* get_dscp_class(int dscp_code)
{
    switch(dscp_code)
    {
        case 48: return "Network control";
        case 46: return "Telephony (EF)";
        case 44: return "Telephony, Capacity-Admitted";
        case 40: return "Signaling";
        case 34:
        case 36:
        case 38: return "Multimedia conferencing";
        case 32: return "Real-time interactive";
        case 24: return "Broadcast video";
        case 16: return "OAM (Operations/Administration/Management)";
        case 26:
        case 28:
        case 30: return "Multimedia streaming";
        case 18:
        case 20:
        case 22: return "Low-latency data";
        case 10:
        case 12:
        case 14: return "High-throughput data";
        case 0: return "Standard (Default Forwarding)";
        default: return "Unknown class";
    }
};  