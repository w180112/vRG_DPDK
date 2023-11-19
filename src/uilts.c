#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_ring.h>
#include "utils.h"

#define BURST_SIZE 32
extern struct rte_ring *rte_ring;

void get_all_lcore_id(struct lcore_map *lcore)
{
    lcore->ctrl_thread = rte_get_next_lcore(rte_lcore_id(), 1, 0);
	lcore->wan_thread = rte_get_next_lcore(lcore->ctrl_thread, 1, 0);
	lcore->down_thread = rte_get_next_lcore(lcore->wan_thread, 1, 0);
	lcore->lan_thread = rte_get_next_lcore(lcore->down_thread, 1, 0);
	lcore->up_thread = rte_get_next_lcore(lcore->lan_thread, 1, 0);
	lcore->gateway_thread = rte_get_next_lcore(lcore->up_thread, 1, 0);
	lcore->timer_thread = rte_get_next_lcore(lcore->gateway_thread, 1, 0);
}

int control_plane_dequeue(void **mail)
{
	U16 burst_size;

	for(;;) {
		burst_size = rte_ring_dequeue_burst(rte_ring, mail, BURST_SIZE, NULL);
		if (likely(burst_size == 0))
			continue;
		break;
	}
	return burst_size;
}
