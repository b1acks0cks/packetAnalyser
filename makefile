
#compiler
CC = gcc

#compiler flags
CFLAGS = -Iipv6 -Iipv4 -Iethernet -Inetworklayer

#Libraries
LIBS = -lpcap

#Source files
SRC = main.c $(wildcard ipv4/get/*.c) $(wildcard ipv6/get/*.c) $(wildcard ipv6/*.c) $(wildcard ethernet/*.c) $(wildcard networklayer/*.c) $(wildcard ipv4/*.c)

#Output binary
BIN = netdragon

#BUILD 

$(BIN): $(SRC)
	$(CC) $(SRC) $(CFLAGS) $(LIBS) -o $(BIN)

