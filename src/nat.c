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
#include "pppd.h"

void 		nat_icmp_learning(struct ether_hdr *eth_hdr, struct ipv4_hdr *ip_hdr, struct icmp_hdr *icmphdr, uint32_t *new_port_id, addr_table_t addr_table[]);
void 		nat_udp_learning(struct ether_hdr *eth_hdr, struct ipv4_hdr *ip_hdr, struct udp_hdr *udphdr, uint32_t *new_port_id, addr_table_t addr_table[]);
void 		nat_tcp_learning(struct ether_hdr *eth_hdr, struct ipv4_hdr *ip_hdr, struct tcp_hdr *tcphdr, uint32_t *new_port_id, addr_table_t addr_table[]);
void 		nat_rule_timer(__attribute__((unused)) struct rte_timer *tim, tPPP_PORT ppp_ports[]);
uint16_t 	get_checksum(const void *const addr, const size_t bytes);

void nat_icmp_learning(struct ether_hdr *eth_hdr, struct ipv4_hdr *ip_hdr, struct icmp_hdr *icmphdr, uint32_t *new_port_id, addr_table_t addr_table[])
{
	*new_port_id = ntohs(icmphdr->icmp_ident + (ip_hdr->src_addr) % 10000);
	if (*new_port_id > 0xffff)
		*new_port_id = *new_port_id / 0xffff + 1000;
	for(int j=1000,shift=0; j<65535; j++) {
		if (addr_table[*new_port_id].is_fill == 1) {
			if (addr_table[*new_port_id].src_ip == ip_hdr->src_addr && addr_table[*new_port_id].dst_ip == ip_hdr->dst_addr )
				return;
			shift++;
			(*new_port_id)++;
		}
		else {
			addr_table[*new_port_id].is_fill = 1;
			break;
		}
	}
	#ifdef _DP_DBG
	puts("learning new icmp nat rule");
	#endif
	rte_memcpy(addr_table[*new_port_id].mac_addr,eth_hdr->s_addr.addr_bytes,6);
	addr_table[*new_port_id].src_ip = ip_hdr->src_addr;
	addr_table[*new_port_id].dst_ip = ip_hdr->dst_addr; 
	addr_table[*new_port_id].port_id = icmphdr->icmp_ident;
}

void nat_udp_learning(struct ether_hdr *eth_hdr, struct ipv4_hdr *ip_hdr, struct udp_hdr *udphdr, uint32_t *new_port_id, addr_table_t addr_table[])
{
	*new_port_id = ntohs(udphdr->src_port + (ip_hdr->src_addr) % 10000);
	if (*new_port_id > 0xffff)
		*new_port_id = *new_port_id / 0xffff + 1000;
	for(int j=1000,shift=0; j<65535; j++) {
		if (addr_table[*new_port_id].is_fill == 1) {
			if (addr_table[*new_port_id].src_ip == ip_hdr->src_addr && addr_table[*new_port_id].dst_ip == ip_hdr->dst_addr)
				return;
			shift++;
			(*new_port_id)++;
		}
		else {
			addr_table[*new_port_id].is_fill = 1;
			break;
		}
	}
	#ifdef _DP_DBG
	puts("learning new udp nat rule");
	#endif
	rte_memcpy(addr_table[*new_port_id].mac_addr,eth_hdr->s_addr.addr_bytes,6);
	addr_table[*new_port_id].src_ip = ip_hdr->src_addr;
	addr_table[*new_port_id].dst_ip = ip_hdr->dst_addr; 
	addr_table[*new_port_id].port_id = udphdr->src_port;
}

void nat_tcp_learning(struct ether_hdr *eth_hdr, struct ipv4_hdr *ip_hdr, struct tcp_hdr *tcphdr, uint32_t *new_port_id, addr_table_t addr_table[])
{
	*new_port_id = ntohs(tcphdr->src_port + (ip_hdr->src_addr) % 10000);
	if (*new_port_id > 0xffff)
		*new_port_id = *new_port_id / 0xffff + 1000;
	for(int j=1000,shift=0; j<65535; j++) {
		if (addr_table[*new_port_id].is_fill == 1) {
			if (addr_table[*new_port_id].src_ip == ip_hdr->src_addr && addr_table[*new_port_id].dst_ip == ip_hdr->dst_addr)
				return;
			shift++;
			(*new_port_id)++;
		}
		else {
			addr_table[*new_port_id].is_fill = 1;
			break;
		}
	}
	#ifdef _DP_DBG
	puts("learning new tcp nat rule");
	#endif
	rte_memcpy(addr_table[*new_port_id].mac_addr,eth_hdr->s_addr.addr_bytes,6);
	addr_table[*new_port_id].src_ip = ip_hdr->src_addr;
	addr_table[*new_port_id].dst_ip = ip_hdr->dst_addr; 
	addr_table[*new_port_id].port_id = tcphdr->src_port;
}

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
	uint8_t user_id;
	for(user_id=0; user_id<MAX_USER; user_id++) {
		for(int i=0; i<65535; i++) {
			if (ppp_ports[user_id].addr_table[i].is_fill == 1) {
				if (ppp_ports[user_id].addr_table[i].is_alive > 0)
					ppp_ports[user_id].addr_table[i].is_alive--;
				else
					memset(&(ppp_ports[user_id].addr_table[i]),0,sizeof(addr_table_t));
			}
		}
	}
}