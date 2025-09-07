#ifndef _VRG_H_
#define _VRG_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_common.h>
#include <rte_atomic.h>
#include <rte_ether.h>
#include <common.h>
#include "dhcpd/dhcp_codec.h"
#include "protocol.h"
#include "pppd/pppd.h"
#include "utils.h"

#define LINK_DOWN           0x0
#define LINK_UP             0x1

enum {
    CLI_QUIT = 0,
    CLI_DISCONNECT,
    CLI_CONNECT,
    CLI_DHCP_START,
    CLI_DHCP_STOP,
};

#define VRG_SUBMODULE_IS_ENABLED 1 << 0
#define VRG_SUBMODULE_IS_DISABLED 1 << 1
#define VRG_SUBMODULE_IS_FORCE_DISABLED 1 << 2
#define VRG_SUBMODULE_IS_SPAWNING 1 << 3
#define VRG_SUBMODULE_IS_TERMINATING 1 << 4
#define VRG_SUBMODULE_IS_SPAWNED 1 << 5
#define VRG_SUBMODULE_IS_TERMINATED 1 << 6

typedef struct {
    U8	is_hsi_enable;	/* hsi switch from northbound */
    U8	is_dhcp_server_enable;	/* dhcp server switch from northbound */
}vrg_feature_switch_t;

struct nic_info {
    char vendor_name[16];
    U16 vendor_id;
    struct rte_ether_addr 	hsi_wan_src_mac;/* vRG WAN side mac addr */
    struct rte_ether_addr 	hsi_lan_mac;    /* vRG LAN side mac addr */
};

/* vRG system data structure */
typedef struct {
    U8 				        cur_user;       /* pppoe alive user count */
    U8 				        loglvl;         /* vRG loglvl */
    BOOL 			        non_vlan_mode;  /* non vlan or vlan mode */
    U16 				    user_count;     /* total vRG subscriptor */
    U16                     base_vlan;      /* started vlan id */
    volatile BOOL	        quit_flag;      /* vRG quit flag */
	U32						lan_ip;         /* vRG LAN side ip */
    struct lcore_map 		lcore;          /* lcore map */
    char                    *unix_sock_path;/* vRG unix socket file path */
    int                     unix_sock_fd;   /* vRG unix socket file descriptor */
    FILE 					*fp;            /* vRG log file pointer */
    struct cmdline 			*cl;
    struct nic_info         nic_info;
    PPP_INFO_t              *ppp_ccb;       /* pppoe control block */
    dhcp_ccb_t              *dhcp_ccb;      /* dhcp control block */
    vrg_feature_switch_t    *vrg_switch;
    struct rte_timer 	    link;           /* for physical link checking timer */
}__rte_cache_aligned VRG_t;

int vrg_start(int argc, char **argv);
void vrg_interrupt();

#ifdef __cplusplus
}
#endif

#endif