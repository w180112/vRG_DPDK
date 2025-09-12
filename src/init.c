#include <rte_ring.h>
#include <rte_errno.h>
#include <rte_mbuf.h>
#include <rte_byteorder.h>
#include <rte_ethdev.h>
#include <linux/ethtool.h>
#include "pppd/pppd.h"
#include "dhcpd/dhcp_codec.h"
#include "dp.h"
#include "init.h"
#include "vrg.h"
#include "dbg.h"
#include "version.h"

#define NUM_MBUFS 		8191
#define MBUF_CACHE_SIZE 512
#define RING_SIZE 		16384

struct rte_ring    *rte_ring, *gateway_q, *uplink_q, *downlink_q;
struct rte_mempool *direct_pool[PORT_AMOUNT];
struct rte_mempool *indirect_pool[PORT_AMOUNT];

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

static int init_mem(VRG_t *vrg_ccb)
{
	char buf[PATH_MAX];
	struct rte_mempool *mp;
    //int socket;

    /* Creates a new mempool in memory to hold the mbufs. */
    for(int i=0; i<PORT_AMOUNT; i++) {
        if (direct_pool[i] == NULL) {
			VRG_LOG(INFO, vrg_ccb->fp, NULL, NULL, "Creating direct mempool on port %i", i);
		    snprintf(buf, sizeof(buf), "pool_direct_%i", i);
		    mp = rte_pktmbuf_pool_create(buf, NUM_MBUFS, MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
		    if (mp == NULL) {
			    VRG_LOG(ERR, vrg_ccb->fp, NULL, NULL, "Cannot create direct mempool");
			    return rte_errno;
		    }
		    direct_pool[i] = mp;
	    }

	    if (indirect_pool[i] == NULL) {
	        VRG_LOG(INFO, vrg_ccb->fp, NULL, NULL, "Creating indirect mempool on port %i", i);
		    snprintf(buf, sizeof(buf), "pool_indirect_%i", i);

		    mp = rte_pktmbuf_pool_create(buf, NUM_MBUFS, MBUF_CACHE_SIZE, 0, 0, rte_socket_id());
		    if (mp == NULL) {
		        VRG_LOG(ERR, vrg_ccb->fp, NULL, NULL, "Cannot create indirect mempool");
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

	rte_eth_macaddr_get(0, &vrg_ccb->nic_info.hsi_lan_mac);
	rte_eth_macaddr_get(1, &vrg_ccb->nic_info.hsi_wan_src_mac);

	/* Initialize all ports. */
	for(portid=0; portid<2; portid++) {
		memset(&dev_info, 0, sizeof(dev_info));
		if (rte_ethtool_get_drvinfo(portid, &dev_info)) {
			VRG_LOG(ERR, vrg_ccb->fp, NULL, NULL, "Error getting info for port %i", portid);
			return rte_errno;
		}
		for(int i=0; vendor[i].vendor_id; i++) {
			if (strcmp((const char *)dev_info.driver, vendor[i].vendor_name) == 0) {
				vrg_ccb->nic_info.vendor_id = vendor[i].vendor_id;
				strcpy(vrg_ccb->nic_info.vendor_name, vendor[i].vendor_name);
				break;
			}
		}

		VRG_LOG(INFO, vrg_ccb->fp, NULL, NULL, "Port %i driver: %s (ver: %s)", portid, dev_info.driver, dev_info.version);
		VRG_LOG(INFO, vrg_ccb->fp, NULL, NULL, "firmware-version: %s", dev_info.fw_version);
		VRG_LOG(INFO, vrg_ccb->fp, NULL, NULL, "bus-info: %s", dev_info.bus_info);

		if (PORT_INIT(vrg_ccb, portid) != 0) {
			VRG_LOG(ERR, vrg_ccb->fp, NULL, NULL, "Cannot init port %"PRIu8 "", portid);
			return -1;
		}
	}

	vrg_ccb->vrg_switch = vrg_malloc(vrg_feature_switch_t, sizeof(vrg_feature_switch_t), 0);
	if (vrg_ccb->vrg_switch == NULL) {
		VRG_LOG(ERR, vrg_ccb->fp, NULL, NULL, "Cannot allocate memory for vrg_switch");
		return -1;
	}
	for(int i=0; i<vrg_ccb->user_count; i++) {
		vrg_ccb->vrg_switch[i].is_hsi_enable = VRG_SUBMODULE_IS_TERMINATED;
		vrg_ccb->vrg_switch[i].is_dhcp_server_enable = VRG_SUBMODULE_IS_TERMINATED;
	}

	vrg_ccb->version = GIT_COMMIT_ID;
	vrg_ccb->build_date = BUILD_TIME;

	return 0;
}

int sys_init(VRG_t *vrg_ccb)
{
    int ret;

    ret = init_mem(vrg_ccb);
    if (ret)
        return ret;
    ret = init_ring();
    if (ret)
		return ret;
		
	signal(SIGINT, (__sighandler_t)vrg_interrupt);

	/* init RTE timer library */
	rte_timer_subsystem_init();

	ret = init_port(vrg_ccb);
	if (ret != 0)
		return ret;

    rte_timer_init(&vrg_ccb->link);
    return 0;
}
