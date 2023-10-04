#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_memcpy.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_arp.h>
#include <rte_icmp.h>
#include <rte_flow.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_timer.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <rte_atomic.h>
#include "pppd.h"

extern U16 user_count;

void nat_rule_timer(__attribute__((unused)) struct rte_timer *tim, PPP_INFO_t *s_ppp_ccb)
{
	//U16 user_id;
	//for(user_id=0; user_id<user_count; user_id++) {
		for(int i=0; i<TOTAL_SOCK_PORT; i++) {
			if (rte_atomic16_read(&s_ppp_ccb->addr_table[i].is_fill) == 1) {
				if (rte_atomic16_read(&s_ppp_ccb->addr_table[i].is_alive) > 0)
					rte_atomic16_sub(&s_ppp_ccb->addr_table[i].is_alive, 1);
				else
					rte_atomic16_set(&s_ppp_ccb->addr_table[i].is_fill, 0);
			}
		}
	//}
}