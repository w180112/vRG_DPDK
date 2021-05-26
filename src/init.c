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

#define NUM_MBUFS 		8191
#define MBUF_CACHE_SIZE 512
#define RING_SIZE 		16384
#define PORT_AMOUNT       2

static int init_mem(void);
static int init_ring(void);
int init_port(struct cmdline *cl);

struct rte_ring    *rte_ring, *gateway_q, *uplink_q, *downlink_q;
struct rte_mempool *direct_pool[PORT_AMOUNT];
struct rte_mempool *indirect_pool[PORT_AMOUNT];
U8					vendor_id = 0;

extern int rte_ethtool_get_drvinfo(U16 port_id, struct ethtool_drvinfo *drv_info);

typedef struct nic_vendor nic_vendor_t;

nic_vendor_t vendor[] = {
	{ "mlx5_pci", MLX5 },
	{ "net_ixgbe", IXGBE },
	{ "net_vmxnet3", VMXNET3 },
	{ "net_ixgbe_vf", IXGBEVF },
	{ "net_i40e", I40E },
	{ "net_i40e_vf", I40EVF },
	{ NULL, 0 }
};

int sys_init(struct cmdline *cl)
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

	ret = init_port(cl);
	if (ret != 0)
		return ret;

	/* init structures */
	for(int i=0; i<MAX_USER; i++) {
		rte_timer_init(&(ppp_ports[i].pppoe));
		rte_timer_init(&(ppp_ports[i].ppp));
		rte_timer_init(&(ppp_ports[i].nat));
		rte_timer_init(&(ppp_ports[i].link));
		rte_timer_init(&(ppp_ports[i].ppp_alive));
		ppp_ports[i].data_plane_start = FALSE;
		rte_atomic16_init(&ppp_ports[i].dhcp_bool);
		rte_atomic16_init(&ppp_ports[i].ppp_bool);
	}

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

int init_port(struct cmdline *cl)
{
	struct ethtool_drvinfo 	dev_info;
	U8 						portid;

	/* Initialize all ports. */
	RTE_ETH_FOREACH_DEV(portid) {
		memset(&dev_info, 0, sizeof(dev_info));
		if (rte_ethtool_get_drvinfo(portid, &dev_info)) {
			RTE_LOG(ERR, EAL, "Error getting info for port %i\n", portid);
			return rte_errno;
		}
		for(int i=0; vendor[i].vendor; i++) {
			if (strcmp((const char *)dev_info.driver, vendor[i].vendor) == 0) {
				vendor_id = vendor[i].vendor_id;
				break;
			}
		}

		cmdline_printf(cl, "vRG> Port %i driver: %s (ver: %s)\n", portid, dev_info.driver, dev_info.version);
		cmdline_printf(cl, "vRG> firmware-version: %s\n", dev_info.fw_version);
		cmdline_printf(cl, "vRG> bus-info: %s\n", dev_info.bus_info);

		if (PPP_PORT_INIT(portid) != 0) {
			RTE_LOG(ERR, EAL, "Cannot init port %"PRIu8 "\n", portid);
			return -1;
		}
	}
	return 0;
}