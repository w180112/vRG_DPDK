#include <rte_flow.h>
#include <linux/if_ether.h>
#include "pppd.h"

#define MAX_PATTERN_NUM		4

struct rte_flow *generate_flow(U16 port_id, U16 rx_q, struct rte_flow_error *error);

struct rte_flow *generate_flow(U16 port_id, U16 rx_q, struct rte_flow_error *error)
{
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[MAX_PATTERN_NUM];
	struct rte_flow_action action[MAX_PATTERN_NUM];
	struct rte_flow *flow = NULL;
	struct rte_flow_action_queue queue = { .index = rx_q };
	struct rte_flow_item_eth eth_spec, eth_mask;
	struct rte_flow_item_vlan vlan_spec, vlan_mask;
	int res;

	memset(pattern,0,sizeof(pattern));
	memset(action,0,sizeof(action));

	/*
	 * set the rule attribute.
	 * in this case only ingress packets will be checked.
	 */
	memset(&attr,0,sizeof(struct rte_flow_attr));
	attr.ingress = 1;

	/*
	 * create the action sequence.
	 * one action only,  move packet to queue
	 */

	action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
	action[0].conf = &queue;
	action[1].type = RTE_FLOW_ACTION_TYPE_END;

	/*
	 * set the first level of the pattern (eth).
	 * since in this example we just want to get the
	 * ipv4 we set this level to allow all.
	 */
	memset(&eth_spec, 0, sizeof(struct rte_flow_item_eth));
	memset(&eth_mask, 0, sizeof(struct rte_flow_item_eth));
	rte_ether_addr_copy(&(ppp_ports[0].lan_mac), &eth_spec.dst);
	for(int i=0; i<ETH_ALEN; i++) {
		eth_mask.dst.addr_bytes[i] = 0xff;
	}
	eth_spec.type = rte_cpu_to_be_16(0x8100);
	eth_mask.type = 0xffff;
	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[0].spec = &eth_spec;
	pattern[0].mask = &eth_mask;

	memset(&vlan_spec,0,sizeof(struct rte_flow_item_vlan));
	memset(&vlan_mask,0,sizeof(struct rte_flow_item_vlan));
	vlan_spec.inner_type = 0x0800;
	vlan_mask.inner_type = 0xffff;
	
	pattern[1].type = RTE_FLOW_ITEM_TYPE_VLAN;
	pattern[1].spec = &vlan_spec;
	pattern[1].mask = &vlan_mask;

	/* the final level must be always type end */
	pattern[2].type = RTE_FLOW_ITEM_TYPE_END;

	res = rte_flow_validate(port_id, &attr, pattern, action, error);
	if (!res)
		flow = rte_flow_create(port_id, &attr, pattern, action, error);

	return flow;
}