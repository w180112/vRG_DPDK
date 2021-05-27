############################################################
# vRG makefile
############################################################

######################################
# Set variable
######################################
# binary name
APP = vrg

# all source are stored in SRCS-y
SRCS-y := *.c
BUILD-dir = ../build

# Build using pkg-config variables if possible
ifneq ($(shell pkg-config --exists libdpdk && echo 0),0)
$(error "no installation of DPDK found")
endif

all: static
.PHONY: static
static: build/$(APP)

PKGCONF ?= pkg-config

INCLUDE += -I. -I../lib/libutil
CFLAGS += $(INCLUDE) -Wall -fPIC -g -std=c99 -D_XOPEN_SOURCE=700 -D_DEFAULT_SOURCE -D_TEST_MODE #-D_DP_DBG -D_NON_VLAN
LDFLAGS += -L../lib/libutil -lutil

PC_FILE := $(shell $(PKGCONF) --path libdpdk 2>/dev/null)
CFLAGS += -O3 $(shell $(PKGCONF) --cflags libdpdk)
LDFLAGS_STATIC = $(shell $(PKGCONF) --static --libs libdpdk)

CFLAGS += -DALLOW_EXPERIMENTAL_API

build/$(APP): $(SRCS-y) Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) $(SRCS-y) -o ../$@ $(LDFLAGS) $(LDFLAGS_STATIC)

build:
	@mkdir -p $(BUILD-dir)
.PHONY: clean
clean:
	test -d $(BUILD-dir) && rm -rf $(BUILD-dir) || true
