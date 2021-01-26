############################################################
# vRG makefile
############################################################

######################################
# Set variable
######################################
# binary name
APP = vrg

# all source are stored in SRCS-y
SRCS-y := pppd.c fsm.c codec.c dpdk_send_recv.c timer.c nat.c ethtool.c dbg.c cmds.c

# Build using pkg-config variables if possible
ifneq ($(shell pkg-config --exists libdpdk && echo 0),0)
$(error "no installation of DPDK found")
endif

all: static
.PHONY: shared static
shared: build/$(APP)-shared
	ln -sf $(APP)-shared build/$(APP)
static: build/$(APP)-static
	ln -sf $(APP)-static build/$(APP)

PKGCONF ?= pkg-config

INCLUDE += -I. -I../lib/libutil -I../lib/dpdk/lib/librte_eal/common
CFLAGS += $(INCLUDE) -Wall -fPIC -g -std=c99 -D_XOPEN_SOURCE=700 -D_DEFAULT_SOURCE #-D_DP_DBG
LDFLAGS += -L../lib/libutil -lutil

PC_FILE := $(shell $(PKGCONF) --path libdpdk 2>/dev/null)
CFLAGS += -O3 $(shell $(PKGCONF) --cflags libdpdk)
LDFLAGS_SHARED = $(shell $(PKGCONF) --libs libdpdk)
LDFLAGS_STATIC = $(shell $(PKGCONF) --static --libs libdpdk)

CFLAGS += -DALLOW_EXPERIMENTAL_API

build/$(APP)-shared: $(SRCS-y) Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS) $(LDFLAGS_SHARED)

build/$(APP)-static: $(SRCS-y) Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS) $(LDFLAGS_STATIC)

build:
	@mkdir -p $@
.PHONY: clean
clean:
	rm -f build/$(APP) build/$(APP)-static build/$(APP)-shared
	test -d build && rmdir -p build || true
