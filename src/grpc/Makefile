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

TARGET = vrg_northbound
SRC = $(wildcard *.cpp)
OBJ = $(SRC:.cpp=.o)
	
.PHONY: $(TARGET)
all: $(TARGET)
######################################
# Compile & Link
# 	Must use \tab key after new line
######################################
$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(TARGET) $(LDFLAGS)

install:
	cp $(TARGET) /usr/local/bin/$(TARGET)

######################################
# Clean 
######################################
clean:
	rm -rf $(OBJ) $(TARGET) .libs
	$(MAKE) -C $(TESTDIR) -f Makefile $@

uninstall:
	rm -f /usr/local/bin/$(TARGET)
