
#ifndef LAYER1_DATA_HEADER
#define LAYER1_DATA_HEADER

typedef unsigned char u_char;

int read_raw_live(char* interface_name);
unsigned char *capture_single(char* interface_name);

#endif