#include<stdint.h>
#include "ecnv6.h"

char* get_ecn_v6(uint8_t ecnCode){
    switch(ecnCode){
        case 0x0: return "Not-ECT";
        case 0x1: return "ECT(1)";
        case 0x2: return "ECT(0)";
        case 0x3: return "CE";
        default: "Unkown";
    }
}