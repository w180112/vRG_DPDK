############################################################
# vRG makefile
############################################################

######################################
# Set variable
######################################	
CC = gcc
INCLUDE = 
CFLAGS = $(INCLUDE) -Wall -g $(shell pkg-config --cflags libdpdk) -O3 -DALLOW_EXPERIMENTAL_API

LDFLAGS = $(shell pkg-config --static --libs libdpdk) -lutils -lconfig -Wl,--start-group -lstdc++ -lgrpc -lgrpc++ -lgrpc_unsecure -lgrpc++_unsecure -lgpr -laddress_sorting -pthread -lprotobuf -lpthread -Wl,--end-group

TARGET = unit-tester
SRC = $(wildcard *.c) $(wildcard pppd/*.c) $(wildcard dhcpd/*.c)

OBJ = $(SRC:.c=.o) $(wildcard ../src/pppd/*.o) $(wildcard ../src/dhcpd/*.o) $(filter-out ../src/main.o, $(wildcard ../src/*.o)) $(filter-out ../northbound/grpc/vrg_grpc_client.o, $(wildcard ../northbound/grpc/*.o))

ifneq ($(shell pkg-config --exists libdpdk && echo 0),0)
$(error "no installation of DPDK found")
endif
	
.PHONY: $(TARGET)
all: $(TARGET)
######################################
# Compile & Link
# 	Must use \tab key after new line
######################################
$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(TARGET) $(LDFLAGS)

######################################
# Clean 
######################################
clean:
	rm -rf $(OBJ) $(TARGET) .libs 
