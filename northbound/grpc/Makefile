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

GRPC_SRC = $(wildcard *.cpp)
PB_SRC = $(wildcard *.cc)
GRPC_OBJ = $(GRPC_SRC:.cpp=.o)
PB_OBJ = $(PB_SRC:.cc=.o)

######################################
# Compile & Link
# 	Must use \tab key after new line
######################################
all:
	protoc --grpc_out=. --plugin=protoc-gen-grpc=`which grpc_cpp_plugin` vrg_cli.proto 
	protoc --cpp_out=. vrg_cli.proto
	$(CC) $(CFLAGS) -c $(GRPC_SRC) $(PB_SRC)

######################################
# Clean 
######################################
clean:
	rm -rf $(GRPC_OBJ) $(PB_OBJ) $(TARGET)
