/*\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\
  DP_CODEC.H

  Designed by THE on JAN 21, 2021
/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\*/

#ifndef _DP_CODEC_H_
#define _DP_CODEC_H_

#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_icmp.h>
#include <rte_tcp.h>
#include <rte_ip.h>
#include <common.h>
#include "pppd.h"
#include "protocol.h"
#include "init.h"
#include "dp_codec.h"

enum {
	gen_port_q = 0,
	up_port_q,
	down_port_q,
	ctrl_port_q,
};

static inline void build_icmp_unreach(VRG_t *vrg_ccb, struct rte_mbuf *pkt, U16 user_index, struct rte_ether_hdr *eth_hdr, vlan_header_t old_vlan_hdr, struct rte_ipv4_hdr *ip_hdr)
{
	vlan_header_t *vlan_header;
    
    struct rte_ether_hdr *new_eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
	rte_ether_addr_copy(&eth_hdr->src_addr, &new_eth_hdr->dst_addr);
	rte_ether_addr_copy(&vrg_ccb->nic_info.hsi_lan_mac, &new_eth_hdr->src_addr);
	new_eth_hdr->ether_type = rte_cpu_to_be_16(VLAN);
	vlan_header = (vlan_header_t *)(new_eth_hdr + 1);
	*vlan_header = old_vlan_hdr;
	struct rte_ipv4_hdr *new_ip_hdr = (struct rte_ipv4_hdr *)(vlan_header + 1);
	*new_ip_hdr = *ip_hdr;
	new_ip_hdr->dst_addr = ip_hdr->src_addr;
	new_ip_hdr->src_addr = vrg_ccb->lan_ip;
	new_ip_hdr->packet_id = 0;
	new_ip_hdr->next_proto_id = IPPROTO_ICMP;
	struct rte_icmp_hdr *icmp_hdr = (struct rte_icmp_hdr *)(new_ip_hdr + 1);
	icmp_hdr->icmp_type	= ICMP_UNREACHABLE;
	icmp_hdr->icmp_code = ICMP_FRAG_NEED_DF_SET;
	icmp_hdr->icmp_ident = 0; //unsed field
	icmp_hdr->icmp_seq_nb = rte_cpu_to_be_16(ETH_MTU - sizeof(struct rte_ipv4_hdr) - sizeof(vlan_header_t) - sizeof(pppoe_header_t) - sizeof(ppp_payload_t)); // MTU size is mentioned here 
	rte_memcpy((char *)(icmp_hdr + 1), (char *)ip_hdr, sizeof(struct rte_ipv4_hdr) + 8);
	new_ip_hdr->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr) + sizeof(struct rte_ipv4_hdr) + 8);
	icmp_hdr->icmp_cksum = 0;
	rte_wmb();
	icmp_hdr->icmp_cksum = (U16)~rte_raw_cksum((const void *)icmp_hdr, sizeof(struct rte_icmp_hdr) + sizeof(struct rte_ipv4_hdr) + 8);
	new_ip_hdr->hdr_checksum = 0;
	new_ip_hdr->hdr_checksum = rte_ipv4_cksum(new_ip_hdr);
	pkt->pkt_len = pkt->data_len = rte_be_to_cpu_16(new_ip_hdr->total_length) + sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t);
	//pkt->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM;
	//pkt->l2_len = sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t);
}

static int encaps_udp(VRG_t *vrg_ccb, struct rte_mbuf **single_pkt, struct rte_ether_hdr *eth_hdr, vlan_header_t *vlan_header, struct rte_ipv4_hdr *ip_hdr, U16	user_index)
{
	struct rte_udp_hdr 	*udphdr;
	U32 				new_port_id;
	pppoe_header_t 		*pppoe_header;
	vlan_header_t		old_vlan_hdr;
	int32_t 			new_pkt_num = 0;

	old_vlan_hdr = *vlan_header;
	if (unlikely((*single_pkt)->pkt_len > (ETH_MTU - (U16)(sizeof(vlan_header_t) + sizeof(pppoe_header_t) + sizeof(ppp_payload_t))))) {
		struct rte_mbuf *pkt = rte_pktmbuf_alloc(direct_pool[0]);
		build_icmp_unreach(vrg_ccb, pkt, user_index, eth_hdr, old_vlan_hdr, ip_hdr);
		if (unlikely(vrg_ccb->non_vlan_mode == TRUE))
			rte_vlan_strip(pkt);
		rte_eth_tx_burst(0, gen_port_q, &pkt, 1);
		rte_pktmbuf_free((*single_pkt));
		new_pkt_num = 0;
	}
	else {
		new_pkt_num = 1;
		ip_hdr->hdr_checksum = 0;
			
		/* for nat */
		//(*single_pkt)->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_UDP_CKSUM;

		udphdr = (struct rte_udp_hdr *)(ip_hdr + 1);
		nat_udp_learning(eth_hdr,ip_hdr,udphdr,&new_port_id,vrg_ccb->ppp_ccb[user_index].addr_table);
		ip_hdr->src_addr = vrg_ccb->ppp_ccb[user_index].hsi_ipv4;
		udphdr->src_port = rte_cpu_to_be_16(new_port_id);
		rte_atomic16_set(&vrg_ccb->ppp_ccb[user_index].addr_table[new_port_id].is_alive, 10);
		ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);
		udphdr->dgram_cksum = 0;
		udphdr->dgram_cksum = rte_ipv4_udptcp_cksum(ip_hdr,udphdr);

		/* for PPPoE */
		eth_hdr = (struct rte_ether_hdr *)rte_pktmbuf_prepend((*single_pkt), (U16)(sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t) + sizeof(pppoe_header_t) + sizeof(ppp_payload_t)));
		rte_ether_addr_copy(&vrg_ccb->nic_info.hsi_wan_src_mac, &eth_hdr->src_addr);
		rte_ether_addr_copy(&vrg_ccb->ppp_ccb[user_index].PPP_dst_mac, &eth_hdr->dst_addr);
		eth_hdr->ether_type = rte_cpu_to_be_16(VLAN);
		vlan_header = (vlan_header_t *)(eth_hdr + 1);
		vlan_header->tci_union.tci_value = old_vlan_hdr.tci_union.tci_value;	
		vlan_header->next_proto = rte_cpu_to_be_16(ETH_P_PPP_SES);
		
		pppoe_header = (pppoe_header_t *)(vlan_header + 1);
		pppoe_header->ver_type = VER_TYPE;
		pppoe_header->code = 0;
		pppoe_header->session_id = vrg_ccb->ppp_ccb[user_index].session_id;
		pppoe_header->length = rte_cpu_to_be_16(((*single_pkt)->data_len) - (U16)(sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t) + sizeof(pppoe_header_t)));
		*(U16 *)(pppoe_header + 1) = rte_cpu_to_be_16(IP_PROTOCOL);
	}

	return new_pkt_num;
}

static int encaps_tcp(VRG_t *vrg_ccb, struct rte_mbuf **single_pkt, struct rte_ether_hdr *eth_hdr, vlan_header_t *vlan_header, struct rte_ipv4_hdr *ip_hdr, U16	user_index)
{
	struct rte_tcp_hdr 	*tcphdr;
	U32 				new_port_id;
	pppoe_header_t 		*pppoe_header;
	vlan_header_t		old_vlan_hdr;
	int32_t 			new_pkt_num = 0;

	old_vlan_hdr = *vlan_header;
	/* for nat */
	//(*single_pkt)->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_TCP_CKSUM;
	//struct rte_mbuf 	*new_pkt;
	if (unlikely((*single_pkt)->pkt_len > (ETH_MTU - (U16)(sizeof(vlan_header_t) + sizeof(pppoe_header_t) + sizeof(ppp_payload_t))))) {
		#if 0 //for re-fragmentation, needed to implementation in the future
		ip_hdr->hdr_checksum = 0;
		tcphdr = (struct rte_tcp_hdr *)(ip_hdr + 1);
		nat_tcp_learning(eth_hdr,ip_hdr,tcphdr,&new_port_id,vrg_ccb.ppp_ccb[user_index].addr_table);
		ori_src_ip = ip_hdr->src_addr;
		ip_hdr->src_addr = vrg_ccb.ppp_ccb[user_index].ipv4;
		tcphdr->src_port = rte_cpu_to_be_16(new_port_id);
		vrg_ccb.ppp_ccb[user_index].addr_table[new_port_id].is_alive = 10;
		ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);
		tcphdr->cksum = 0;
		tcphdr->cksum = rte_ipv4_udptcp_cksum(ip_hdr,tcphdr);

		ip_hdr->fragment_offset = 0;
		//printf("pkt len = %u, data len = %u\n", (*single_pkt)->pkt_len, (*single_pkt)->data_len);
		new_pkt_num = rte_ipv4_fragment_packet((*single_pkt), &new_pkt, 6, IPV4_MTU_DEFAULT - sizeof(vlan_header_t) - sizeof(pppoe_header_t) - sizeof(ppp_payload_t), direct_pool[0], indirect_pool[0]);
		rte_pktmbuf_free((*single_pkt));
		if (unlikely(new_pkt_num < 0)) {
			printf("pkt fragmentation error: %s\n", rte_strerror(new_pkt_num));
			return -1;
		}

		for ((*single_pkt)=new_pkt; (*single_pkt)!=NULL; (*single_pkt)=(*single_pkt)->next) {
			ip_hdr = (struct rte_ipv4_hdr *)(rte_pktmbuf_mtod((*single_pkt),unsigned char *));
			tcphdr = (struct rte_tcp_hdr *)(ip_hdr + 1);
			struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)rte_pktmbuf_prepend((*single_pkt), (U16)(sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t) + sizeof(pppoe_header_t) + sizeof(ppp_payload_t)));
			if (eth_hdr == NULL) {
				rte_panic("No headroom in mbuf.\n");
			}

			//(*single_pkt)->ol_flags = PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_TCP_CKSUM;
			(*single_pkt)->l2_len = sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t) + sizeof(pppoe_header_t) + sizeof(ppp_payload_t);

			rte_memcpy(eth_hdr->src_addr.addr_bytes,vrg_ccb.ppp_ccb[user_index].src_mac,ETH_ALEN);
			rte_memcpy(eth_hdr->dst_addr.addr_bytes,vrg_ccb.ppp_ccb[user_index].dst_mac,ETH_ALEN);

			//rte_ether_addr_copy(&vrg_ccb.ppp_ccb[user_index].src_mac, &eth_hdr->src_addr);
			//rte_ether_addr_copy(&vrg_ccb.ppp_ccb[user_index].dst_mac, &eth_hdr->dst_addr);
			eth_hdr->ether_type = rte_cpu_to_be_16(VLAN);
			vlan_header = (vlan_header_t *)(eth_hdr + 1);
			vlan_header->tci_union.tci_value = old_vlan_hdr.tci_union.tci_value;
			vlan_header->next_proto = rte_cpu_to_be_16(ETH_P_PPP_SES);
			pppoe_header = (pppoe_header_t *)(vlan_header + 1);
			pppoe_header->ver_type = VER_TYPE;
			pppoe_header->code = 0;
			pppoe_header->session_id = vrg_ccb.ppp_ccb[user_index].session_id;
			pppoe_header->length = rte_cpu_to_be_16(((*single_pkt)->data_len) - (U16)(sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t) + sizeof(pppoe_header_t)));
			*(U16 *)(pppoe_header + 1) = rte_cpu_to_be_16(IP_PROTOCOL);
			ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);
			tcphdr->cksum = rte_ipv4_udptcp_cksum(ip_hdr,tcphdr);
		}
		(*single_pkt) = new_pkt;
		#else
		struct rte_mbuf *pkt = rte_pktmbuf_alloc(direct_pool[0]);
		build_icmp_unreach(vrg_ccb, pkt, user_index, eth_hdr, old_vlan_hdr, ip_hdr);
		if (unlikely(vrg_ccb->non_vlan_mode == TRUE))
			rte_vlan_strip(pkt);
		rte_eth_tx_burst(0, gen_port_q, &pkt, 1);
		rte_pktmbuf_free((*single_pkt));
		new_pkt_num = 0;
		#endif
	}

	else {
		ip_hdr->hdr_checksum = 0;
		tcphdr = (struct rte_tcp_hdr *)(ip_hdr + 1);
		nat_tcp_learning(eth_hdr,ip_hdr,tcphdr,&new_port_id,vrg_ccb->ppp_ccb[user_index].addr_table);
		ip_hdr->src_addr = vrg_ccb->ppp_ccb[user_index].hsi_ipv4;
		tcphdr->src_port = rte_cpu_to_be_16(new_port_id);
		rte_atomic16_set(&vrg_ccb->ppp_ccb[user_index].addr_table[new_port_id].is_alive, 10);
		ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);
		tcphdr->cksum = 0;
		tcphdr->cksum = rte_ipv4_udptcp_cksum(ip_hdr,tcphdr);

		new_pkt_num = 1;
		eth_hdr = (struct rte_ether_hdr *)rte_pktmbuf_prepend((*single_pkt), (U16)(sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t) + sizeof(pppoe_header_t) + sizeof(ppp_payload_t)));
		/* for PPPoE */
		rte_ether_addr_copy(&vrg_ccb->nic_info.hsi_wan_src_mac, &eth_hdr->src_addr);
		rte_ether_addr_copy(&vrg_ccb->ppp_ccb[user_index].PPP_dst_mac, &eth_hdr->dst_addr);
		eth_hdr->ether_type = rte_cpu_to_be_16(VLAN);
		vlan_header = (vlan_header_t *)(eth_hdr + 1);
		vlan_header->tci_union.tci_value = old_vlan_hdr.tci_union.tci_value;	
		vlan_header->next_proto = rte_cpu_to_be_16(ETH_P_PPP_SES);
		
		pppoe_header = (pppoe_header_t *)(vlan_header + 1);
		pppoe_header->ver_type = VER_TYPE;
		pppoe_header->code = 0;
		pppoe_header->session_id = vrg_ccb->ppp_ccb[user_index].session_id;
		pppoe_header->length = rte_cpu_to_be_16(((*single_pkt)->data_len) - (U16)(sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t) + sizeof(pppoe_header_t)));
		*(U16 *)(pppoe_header + 1) = rte_cpu_to_be_16(IP_PROTOCOL);
	}
	return new_pkt_num;
}

static int decaps_udp(VRG_t *vrg_ccb, struct rte_mbuf *single_pkt, struct rte_ether_hdr *eth_hdr, vlan_header_t *vlan_header, struct rte_ipv4_hdr *ip_hdr, U16	user_index)
{
	struct rte_udp_hdr 	*udphdr;
	U16 			ori_port_id;

	/*if (single_pkt->data_len > (ETH_MTU - (U16)(sizeof(pppoe_header_t) + sizeof(ppp_payload_t)))) {
		rte_pktmbuf_free(single_pkt);
		return 0;
	}*/
	//single_pkt->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM/* | PKT_TX_UDP_CKSUM*/;
	udphdr = (struct rte_udp_hdr *)(ip_hdr + 1);
	ori_port_id = rte_cpu_to_be_16(udphdr->dst_port);
	rte_ether_addr_copy(&vrg_ccb->nic_info.hsi_lan_mac, &eth_hdr->src_addr);
	rte_ether_addr_copy(&vrg_ccb->ppp_ccb[user_index].addr_table[ori_port_id].mac_addr, &eth_hdr->dst_addr);
	ip_hdr->dst_addr = vrg_ccb->ppp_ccb[user_index].addr_table[ori_port_id].src_ip;
	udphdr->dst_port = vrg_ccb->ppp_ccb[user_index].addr_table[ori_port_id].port_id;
	rte_atomic16_set(&vrg_ccb->ppp_ccb[user_index].addr_table[ori_port_id].is_alive, 10);
	ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);
	udphdr->dgram_cksum = 0;
	udphdr->dgram_cksum = rte_ipv4_udptcp_cksum(ip_hdr,udphdr);

	return 1;
}

static int decaps_tcp(VRG_t *vrg_ccb, struct rte_mbuf *single_pkt, struct rte_ether_hdr *eth_hdr, vlan_header_t *vlan_header, struct rte_ipv4_hdr *ip_hdr, U16	user_index)
{
	struct rte_tcp_hdr 	*tcphdr;
	U16 			ori_port_id;

	/*if (single_pkt->data_len > (ETH_MTU - (U16)(sizeof(pppoe_header_t) + sizeof(ppp_payload_t)))) {
		rte_pktmbuf_free(single_pkt);
		return 0;
	}*/
	//single_pkt->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM/* | PKT_TX_TCP_CKSUM*/;
	tcphdr = (struct rte_tcp_hdr *)(ip_hdr + 1);
	ori_port_id = rte_cpu_to_be_16(tcphdr->dst_port);
	rte_ether_addr_copy(&vrg_ccb->nic_info.hsi_lan_mac, &eth_hdr->src_addr);
	rte_ether_addr_copy(&vrg_ccb->ppp_ccb[user_index].addr_table[ori_port_id].mac_addr, &eth_hdr->dst_addr);
	ip_hdr->dst_addr = vrg_ccb->ppp_ccb[user_index].addr_table[ori_port_id].src_ip;
	tcphdr->dst_port = vrg_ccb->ppp_ccb[user_index].addr_table[ori_port_id].port_id;
	rte_atomic16_set(&vrg_ccb->ppp_ccb[user_index].addr_table[ori_port_id].is_alive, 10);
	ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);
	tcphdr->cksum = 0;
	tcphdr->cksum = rte_ipv4_udptcp_cksum(ip_hdr,tcphdr);

	return 1;
}

#endif