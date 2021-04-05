#include <rte_ring.h>
#include <rte_errno.h>
#include <rte_mbuf.h>
#include <rte_byteorder.h>
#include "pppd.h"
#include "dhcp_codec.h"

#define NUM_MBUFS 		8191
#define MBUF_CACHE_SIZE 512
#define RING_SIZE 		16384
#define PORT_AMOUNT       2

static int init_mem(void);
static int init_ring(void);

struct rte_ring    *rte_ring, *rg_func_q, *uplink_q, *downlink_q;
struct rte_mempool *direct_pool[PORT_AMOUNT];
struct rte_mempool *indirect_pool[PORT_AMOUNT];

int sys_init(void)
{
    int ret;

    ret = init_mem();
    if (ret)
        return ret;
    ret = init_ring();
    if (ret)
        return ret;

    //signal(SIGTERM,(__sighandler_t)PPP_bye);
	signal(SIGINT,(__sighandler_t)PPP_int);

	/* init RTE timer library */
	rte_timer_subsystem_init();

    return 0;
}

static int init_mem(void)
{
	char buf[PATH_MAX];
	struct rte_mempool *mp;
    //int socket;

    /* Creates a new mempool in memory to hold the mbufs. */
    for(int i=0; i<PORT_AMOUNT; i++) {
        /*if (rte_lcore_is_enabled(i) == 0)
			continue;

		socket = rte_lcore_to_socket_id(i);

		if (socket == SOCKET_ID_ANY)
			socket = 0;*/
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
	rg_func_q = rte_ring_create("rg_function",RING_SIZE,rte_socket_id(),0);
	if (!rg_func_q)
        return rte_errno;
    uplink_q = rte_ring_create("upstream",RING_SIZE,rte_socket_id(),0);
	if (!uplink_q)
        return rte_errno;
    downlink_q = rte_ring_create("downstream",RING_SIZE,rte_socket_id(),0);
    if (!downlink_q)
        return rte_errno;

    return 0;
}
