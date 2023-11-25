#include <rte_eal.h>
#include <rte_lcore.h>
#include "utils.h"

void get_all_lcore_id(struct lcore_map *lcore)
{
    lcore->ctrl_thread = rte_get_next_lcore(rte_lcore_id(), 1, 0);
	lcore->wan_thread = rte_get_next_lcore(lcore->ctrl_thread, 1, 0);
	lcore->down_thread = rte_get_next_lcore(lcore->wan_thread, 1, 0);
	lcore->lan_thread = rte_get_next_lcore(lcore->down_thread, 1, 0);
	lcore->up_thread = rte_get_next_lcore(lcore->lan_thread, 1, 0);
	lcore->gateway_thread = rte_get_next_lcore(lcore->up_thread, 1, 0);
	lcore->timer_thread = rte_get_next_lcore(lcore->gateway_thread, 1, 0);
	lcore->northbound_thread = rte_get_next_lcore(lcore->timer_thread, 1, 0);
}
