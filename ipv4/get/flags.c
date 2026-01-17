#include<stdlib.h>
#include<string.h>
#include<stdio.h>
#include<stdint.h>
#include "flags.h"

// takes the raw BITS of a flag as an integer and returns an that gives more information about the flags

char** get_flags(uint8_t flags){

    char flag[3];
    
    // convert the bits into an array
    flag[0] = (flags & 0x1) >> 0;
    flag[1] = (flags & 0x2) >> 1;
    flag[2] = (flags & 0x4) >> 2;

    int maximum_str_len = 21;
    int number_of_buffers = 3;
    char **result = malloc(maximum_str_len * number_of_buffers );   
    for(int i = 0; i < 3; i++){
        switch(i)
        {
        case 0:
            result[i] = malloc(maximum_str_len);
            if(!flag[i])
            {
                strncpy(result[0], "Reserved", maximum_str_len);
            }
            else
            {
                strncpy(result[0], "Not set", maximum_str_len);
            }
            break;
        case 1:
            result[i] = malloc(maximum_str_len);
            if(!flag[i])
            {
                strncpy(result[1], "Can be fragmented", maximum_str_len);
            }
            else
            {
                strncpy(result[1], "Must not be fragmented", maximum_str_len);
            }
            break;
        case 2:
            result[i] = malloc(maximum_str_len );
            if(!flag[i])
            {
                strncpy(result[2], "More fragments follow", maximum_str_len);
            }
            else
            {
                strncpy(result[2], "No fragments follow", maximum_str_len);
            }
            break;
        }
    }

    return result;
}

void free_flags(char** flags_buffer){
    if( flags_buffer != NULL){
        free(flags_buffer[0]);
        free(flags_buffer[1]);
        free(flags_buffer[2]);
        free(flags_buffer);
    }
    else
        return;
};
