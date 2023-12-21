############################################################
# vRG makefile
############################################################

######################################
# Set variable
######################################	
CC = gcc
INCLUDE = -Inorthbound/grpc
CFLAGS = $(INCLUDE) -Wall -g $(shell pkg-config --cflags libdpdk) -O3 -DALLOW_EXPERIMENTAL_API -D_TEST_MODE #-Wextra -fsanitize=address

LDFLAGS = $(shell pkg-config --static --libs libdpdk) -lutils -lconfig -Wl,--start-group -lstdc++ -lgrpc -lgrpc++ -lgrpc_unsecure -lgrpc++_unsecure -lgpr -laddress_sorting -pthread -lprotobuf -lpthread -Wl,--end-group

TARGET = vrg
SRC = $(wildcard src/*.c) $(wildcard src/pppd/*.c) $(wildcard src/dhcpd/*.c)
OBJ = $(SRC:.c=.o)

GRPCDIR = northbound/grpc
GRPC_SRC = $(filter-out $(GRPCDIR)/*client.cpp, $(wildcard $(GRPCDIR)/*.cpp))
PB_SRC = $(wildcard $(GRPCDIR)/*.cc)
GRPC_OBJ = $(GRPC_SRC:.cpp=.o)
PB_OBJ = $(PB_SRC:.cc=.o)

TESTDIR = unit_test
TESTBIN = unit-tester

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
	${MAKE} -C $(GRPCDIR)
	$(CC) $(CFLAGS) $(OBJ) $(GRPC_OBJ) $(PB_OBJ) -o $(TARGET) $(LDFLAGS)

install:
	cp $(TARGET) /usr/local/bin/$(TARGET)

test: $(TARGET)
	${MAKE} -C $(TESTDIR)
	ulimit -s 16384 && ./$(TESTDIR)/$(TESTBIN)

######################################
# Clean 
######################################
clean:
	rm -rf $(OBJ) $(TARGET) .libs
	$(MAKE) -C $(TESTDIR) -f Makefile $@
	$(MAKE) -C $(GRPCDIR) -f Makefile $@

uninstall:
	rm -f /usr/local/bin/$(TARGET)
