############################################################
# vRG makefile
############################################################

######################################
# Set variable
######################################	
CC = gcc
INCLUDE = -I../../src -I../grpc
CFLAGS = $(INCLUDE) -Wall -g $(shell pkg-config --cflags libdpdk) -O3 -DALLOW_EXPERIMENTAL_API -D_TEST_MODE #-Wextra -fsanitize=address

LDFLAGS = $(shell pkg-config --static --libs libdpdk) -lutils -lconfig -Wl,--start-group -lstdc++ -lgrpc -lgrpc++ -lgrpc_unsecure -lgrpc++_unsecure -lgpr -laddress_sorting -pthread -lprotobuf -lpthread -Wl,--end-group

TARGET = vrg_cli
SRC = $(wildcard *.c)
OBJ = $(SRC:.c=.o)

GRPCDIR = ../grpc
GRPC_SRC = $(GRPCDIR)/vrg_grpc_client.cpp
PB_SRC = $(wildcard $(GRPCDIR)/*.cc)
GRPC_OBJ = $(GRPC_SRC:.cpp=.o)
PB_OBJ = $(PB_SRC:.cc=.o)

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
	$(CC) $(CFLAGS) $(OBJ) $(GRPC_OBJ) $(PB_OBJ) -o $(TARGET) $(LDFLAGS)

######################################
# Clean 
######################################
clean:
	rm -rf $(OBJ) $(TARGET) .libs
