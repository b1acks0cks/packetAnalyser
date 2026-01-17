
#ifndef TCP_FLAGS_H
#define TCP_FLAGS_H

char** get_tcp_flags(unsigned char flagbyte);
void free_tcp_flags(char** flags);

#endif