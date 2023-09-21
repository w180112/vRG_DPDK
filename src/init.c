#include <rte_ring.h>
#include <rte_errno.h>
#include <rte_mbuf.h>
#include <rte_byteorder.h>
#include <rte_ethdev.h>
#include <linux/ethtool.h>
#include "pppd.h"
#include "dhcp_codec.h"
#include "dp.h"
#include "init.h"
#include "vrg.h"

#define NUM_MBUFS 		8191
#define MBUF_CACHE_SIZE 512
#define RING_SIZE 		16384

static int init_mem(void);
static int init_ring(void);
int init_port(VRG_t *vrg_ccb);

struct rte_ring    *rte_ring, *gateway_q, *uplink_q, *downlink_q;
struct rte_mempool *direct_pool[PORT_AMOUNT];
struct rte_mempool *indirect_pool[PORT_AMOUNT];
extern U16 			user_count;

extern int rte_ethtool_get_drvinfo(U16 port_id, struct ethtool_drvinfo *drv_info);

struct nic_info vendor[] = {
	{ "mlx5_pci", MLX5 },
	{ "net_ixgbe", IXGBE },
	{ "net_vmxnet3", VMXNET3 },
	{ "net_ixgbe_vf", IXGBEVF },
	{ "net_i40e", I40E },
	{ "net_i40e_vf", I40EVF },
	{ "", 0 }
};

int sys_init(VRG_t *vrg_ccb)
{
    int ret;

    ret = init_mem();
    if (ret)
        return ret;
    ret = init_ring();
    if (ret)
		return ret;
		
	signal(SIGINT,(__sighandler_t)PPP_int);

	/* init RTE timer library */
	rte_timer_subsystem_init();

	ret = init_port(vrg_ccb);
	if (ret != 0)
		return ret;

    rte_timer_init(&vrg_ccb->link);
    return 0;
}

static int init_mem(void)
{
	char buf[PATH_MAX];
	struct rte_mempool *mp;
    //int socket;

    /* Creates a new mempool in memory to hold the mbufs. */
    for(int i=0; i<PORT_AMOUNT; i++) {
        if (direct_pool[i] == NULL) {
		    RTE_LOG(INFO, EAL, "Creating direct mempool on port %i\n", i);
		    snprintf(buf, sizeof(buf), "pool_direct_%i", i);
		    mp = rte_pktmbuf_pool_create(buf, NUM_MBUFS, MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
		    if (mp == NULL) {
			    RTE_LOG(ERR, EAL, "Cannot create direct mempool\n");
			    return rte_errno;
		    }
		    direct_pool[i] = mp;
	    }

	    if (indirect_pool[i] == NULL) {
	        RTE_LOG(INFO, EAL, "Creating indirect mempool on port %i\n", i);
		    snprintf(buf, sizeof(buf), "pool_indirect_%i", i);

		    mp = rte_pktmbuf_pool_create(buf, NUM_MBUFS, MBUF_CACHE_SIZE, 0, 0, rte_socket_id());
		    if (mp == NULL) {
		        RTE_LOG(ERR, EAL, "Cannot create indirect mempool\n");
			    return rte_errno;
		    }
		    indirect_pool[i] = mp;
        }
	}

	return 0;
}

static int init_ring(void)
{
    rte_ring = rte_ring_create("state_machine",RING_SIZE,rte_socket_id(),0);
    if (!rte_ring)
		return rte_errno;
	gateway_q = rte_ring_create("rg-function",RING_SIZE,rte_socket_id(),0);
	if (!gateway_q)
        return rte_errno;
    uplink_q = rte_ring_create("upstream",RING_SIZE,rte_socket_id(),0);
	if (!uplink_q)
        return rte_errno;
    downlink_q = rte_ring_create("downstream",RING_SIZE,rte_socket_id(),0);
    if (!downlink_q)
        return rte_errno;

    return 0;
}

int init_port(VRG_t *vrg_ccb)
{
	struct ethtool_drvinfo 	dev_info;
	U8 						portid;
	struct cmdline 			*cl = vrg_ccb->cl;

	rte_eth_macaddr_get(0, &vrg_ccb->nic_info.hsi_lan_mac);
	rte_eth_macaddr_get(1, &vrg_ccb->nic_info.hsi_wan_src_mac);

	/* Initialize all ports. */
	for(portid=0; portid<2; portid++) {
		memset(&dev_info, 0, sizeof(dev_info));
		if (rte_ethtool_get_drvinfo(portid, &dev_info)) {
			RTE_LOG(ERR, EAL, "Error getting info for port %i\n", portid);
			return rte_errno;
		}
		for(int i=0; vendor[i].vendor_id; i++) {
			if (strcmp((const char *)dev_info.driver, vendor[i].vendor_name) == 0) {
				vrg_ccb->nic_info.vendor_id = vendor[i].vendor_id;
				strcpy(vrg_ccb->nic_info.vendor_name, vendor[i].vendor_name);
				break;
			}
		}

		cmdline_printf(cl, "vRG> Port %i driver: %s (ver: %s)\n", portid, dev_info.driver, dev_info.version);
		cmdline_printf(cl, "vRG> firmware-version: %s\n", dev_info.fw_version);
		cmdline_printf(cl, "vRG> bus-info: %s\n", dev_info.bus_info);

		if (PORT_INIT(vrg_ccb, portid) != 0) {
			RTE_LOG(ERR, EAL, "Cannot init port %"PRIu8 "\n", portid);
			return -1;
		}
	}
	return 0;
}