############################################################
# vRG northbound makefile
############################################################

######################################
# Set variable
######################################	
CC = g++
INCLUDE =
CFLAGS = $(INCLUDE) -Wall -g -O3

LDFLAGS = -lutils 

PROTO_SRC = vrg_cli.proto
GRPC_SRC = $(wildcard *.cpp)
PB_HDR    = $(PB_SRC:.cc=.h)
PB_SRC = $(PROTO_SRC:.proto=.pb.cc) $(PROTO_SRC:.proto=.grpc.pb.cc)
GRPC_OBJ = $(GRPC_SRC:.cpp=.o)

######################################
# Compile & Link
# 	Must use \tab key after new line
######################################
all:
	protoc --grpc_out=$(CURDIR) --plugin=protoc-gen-grpc=`which grpc_cpp_plugin` $(PROTO_SRC)
	protoc --cpp_out=$(CURDIR) $(PROTO_SRC)
	$(CC) $(CFLAGS) -c $(GRPC_SRC) $(PB_SRC)

######################################
# Clean 
######################################
clean:
	rm -rf $(PB_SRC) $(PB_HDR) $(GRPC_OBJ)
