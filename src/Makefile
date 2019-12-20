############################################################
# pppoe makefile
############################################################

######################################
# Set variable
######################################
LDLIBS += -L../lib/com_util -lcom_util
APP = pppoeclient

# all source are stored in SRCS-y
SRCS-y := pppd.c fsm.c codec.c dpdk_send_recv.c timer.c nat.c ethtool.c dbg.c cmds.c

# Build using pkg-config variables if possible
$(shell pkg-config --exists libdpdk)

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overridden by command line or environment
RTE_TARGET ?= x86_64-native-linux-gcc

include $(RTE_SDK)/mk/rte.vars.mk

INCLUDE += -I. -I../includes/com_util -I$(RTE_SDK)/lib/librte_eal/common
CFLAGS += $(INCLUDE) -Wall -fPIC -g -std=c99 -D_XOPEN_SOURCE=700 -D_BSD_SOURCE #-D_DP_DBG

CFLAGS += -O3
CFLAGS += $(WERROR_FLAGS)

include $(RTE_SDK)/mk/rte.app.mk
