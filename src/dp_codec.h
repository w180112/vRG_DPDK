#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_icmp.h>
#include <rte_ip.h>
#include "pppd.h"
#include "pppoeclient.h"

extern tPPP_PORT				ppp_ports[MAX_USER];

static inline void build_icmp_unreach(struct rte_mbuf *pkt, uint16_t user_index, struct rte_ether_hdr *eth_hdr, vlan_header_t old_vlan_hdr, struct rte_ipv4_hdr *ip_hdr)
{
	vlan_header_t *vlan_header;
    
    struct rte_ether_hdr *new_eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
	rte_ether_addr_copy(&eth_hdr->s_addr, &new_eth_hdr->d_addr);
	rte_ether_addr_copy(&ppp_ports[user_index].lan_mac, &new_eth_hdr->s_addr);
	new_eth_hdr->ether_type = rte_cpu_to_be_16(VLAN);
	vlan_header = (vlan_header_t *)(new_eth_hdr + 1);
	*vlan_header = old_vlan_hdr;
	struct rte_ipv4_hdr *new_ip_hdr = (struct rte_ipv4_hdr *)(vlan_header + 1);
	*new_ip_hdr = *ip_hdr;
	new_ip_hdr->dst_addr = ip_hdr->src_addr;
	new_ip_hdr->src_addr = ppp_ports[user_index].lan_ip;
	new_ip_hdr->packet_id = 0;
	new_ip_hdr->next_proto_id = IPPROTO_ICMP;
	struct rte_icmp_hdr *icmp_hdr = (struct rte_icmp_hdr *)(new_ip_hdr + 1);
	icmp_hdr->icmp_type	= 0x3;
	icmp_hdr->icmp_code = 0x4;
	icmp_hdr->icmp_ident = 0; //unsed field
	icmp_hdr->icmp_seq_nb = rte_cpu_to_be_16(ETH_MTU - sizeof(struct rte_ipv4_hdr) - sizeof(vlan_header_t) - sizeof(pppoe_header_t) - sizeof(ppp_payload_t)); // MTU size is mentioned here 
	rte_memcpy((char *)(icmp_hdr + 1), (char *)ip_hdr, sizeof(struct rte_ipv4_hdr) + 8);
	new_ip_hdr->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr) + sizeof(struct rte_ipv4_hdr) + 8);
	icmp_hdr->icmp_cksum = 0;
	rte_wmb();
	icmp_hdr->icmp_cksum = (uint16_t)~rte_raw_cksum((const void *)icmp_hdr, sizeof(struct rte_icmp_hdr) + sizeof(struct rte_ipv4_hdr) + 8);
	new_ip_hdr->hdr_checksum = 0;
	new_ip_hdr->hdr_checksum = rte_ipv4_cksum(new_ip_hdr);
	pkt->pkt_len = pkt->data_len = rte_be_to_cpu_16(new_ip_hdr->total_length) + sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t);
	//pkt->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM;
	//pkt->l2_len = sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t);
}