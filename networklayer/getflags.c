#include "getflags.h"
#include<stdint.h>
#include<string.h>
#include<stdlib.h>
//from most to least signifcant bit
static const char *flags[8] = {
    [0] = "CWR",
    [1] = "ECE",
    [2] = "URG",
    [3] = "ACK",
    [4] = "PSH",
    [5] = "RST",
    [6] = "SYN",
    [7] = "FIN"
};



char** get_tcp_flags(unsigned char inputbyte){
    // start loop from most significant bit
    int flag_size = 5;
    char** result = malloc(8 * sizeof(char*) );

    for(int i = 0; i < 8; i++){
        result[i] = malloc(flag_size);
    }
    for(int i = 8; i > 0; i--){
        if ( (inputbyte & (1 << (i - 1))) != 0){
            // if 1 (true) then we have a bit there
            strcpy(result[8-i], flags[8 - i]);
        }
        else
        {
            free(result[8-i]);
            result[8-i] = NULL;
        }
    }
    return result;
}

void free_tcp_flags(char** flags){
    for(int i = 0; i < 8; i++){
        free(flags[i]);
    }

    free(flags);
}