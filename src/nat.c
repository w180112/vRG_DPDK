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

void 		nat_rule_timer(__attribute__((unused)) struct rte_timer *tim, tPPP_PORT ppp_ports[]);
uint16_t 	get_checksum(const void *const addr, const size_t bytes);

#pragma GCC diagnostic push  // require GCC 4.6
#pragma GCC diagnostic ignored "-Wcast-qual"
uint16_t get_checksum(const void *const addr, const size_t bytes)
{
	const uint16_t 	*word;
	uint32_t 		sum;
	uint16_t 		checksum;
	size_t 			nleft;

	assert(addr);
	assert(bytes > 8 - 1);
	word = (const uint16_t *)addr;
	nleft = bytes;
  
	for(sum=0; nleft>1; nleft-=2) {
    	sum += *word;
      	++word;
    }
  	sum += nleft ? *(uint8_t *)word : 0;
  	sum = (sum >> 16) + (sum & 0xffff);
  	sum += (sum >> 16);
  
  	return checksum = ~sum;
}
#pragma GCC diagnostic pop   // require GCC 4.6

void nat_rule_timer(__attribute__((unused)) struct rte_timer *tim, tPPP_PORT ppp_ports[])
{
	uint16_t user_id;
	for(user_id=0; user_id<MAX_USER; user_id++) {
		for(int i=0; i<65535; i++) {
			if (ppp_ports[user_id].addr_table[i].is_fill == 1) {
				if (ppp_ports[user_id].addr_table[i].is_alive > 0)
					ppp_ports[user_id].addr_table[i].is_alive--;
				else
					ppp_ports[user_id].addr_table[i].is_fill = 0;
			}
		}
	}
}