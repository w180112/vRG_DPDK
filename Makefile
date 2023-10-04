############################################################
# vRG makefile
############################################################

######################################
# Set variable
######################################	
CC = gcc
INCLUDE = 
CFLAGS = $(INCLUDE) -Wall -g $(shell pkg-config --cflags libdpdk) -O3 -DALLOW_EXPERIMENTAL_API

LDFLAGS = $(shell pkg-config --static --libs libdpdk) -lutils -lconfig

TARGET = vrg
SRC = $(wildcard src/*.c)
OBJ = $(SRC:.c=.o)

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
	libtool --mode=link $(CC) $(CFLAGS) $(OBJ) -o $(TARGET) $(LDFLAGS)

install:
	cp $(TARGET) /usr/local/bin/$(TARGET)

test:
	${MAKE} -C $(TESTDIR)
	./$(TESTDIR)/$(TESTBIN)

######################################
# Clean 
######################################
clean:
	rm -rf $(OBJ) $(TARGET) .libs
	$(MAKE) -C $(TESTDIR) -f Makefile $@

uninstall:
	rm -f /usr/local/bin/$(TARGET)
