
# include make configuration

CROSS=
STRIP	=$(CROSS)strip
CC=$(CROSS)gcc
LINK=$(CROSS)ar

EXEC=

#CFLAGS=  -I./ -DMDC_MDIO_OPERATION -D_LITTLE_ENDIAN -Wall -O2  
CFLAGS=  -I./ -Wall -O2 -D_BSD_SOURCE -std=c99 -D_XOPEN_SOURCE=700

%.o: %.c
	$(CC) $(CFLAGS) -c $<

SRC = util.c os_timer.c ipc.c ip_codec.c md5.c
OBJ = $(SRC:.c=.o)
TARGET = com_util

all:com

com:$(OBJS)
	$(CC) $(CFLAGS) -c $(SRC) 
#	$(CC) $(CFLAGS) -o $(TARGET) $(OBJ) //gen .exe from .obj
	$(LINK) rcs lib$(TARGET).a $(OBJ)
#	sudo cp -f lib$(TARGET).a ..

clean:
	-rm -f $(TARGET) $(OBJ) lib$(TARGET).a
