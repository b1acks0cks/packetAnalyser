#include<stdint.h>
#include "ecn.h"

char* get_ecn(uint8_t ecnCode){
    switch(ecnCode){
        case 0x0: return "Not-ECT";
        case 0x1: return "ECT(1)";
        case 0x2: return "ECT(0)";
        case 0x3: return "CE";
        default: "Unkown";
    }
}