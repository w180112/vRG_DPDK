#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_arp.h>
#include <rte_ip.h>
#include <rte_icmp.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_timer.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <rte_memcpy.h>
#include <rte_atomic.h>
#include "pppoeclient.h"
#include "nat.h"

#define RX_RING_SIZE 128

#define TX_RING_SIZE 512

#define BURST_SIZE 32

#define	IPV4_MTU_DEFAULT	RTE_ETHER_MTU
#define	IPV6_MTU_DEFAULT	RTE_ETHER_MTU

enum {
	gen_port_q = 0,
	tcp_port_q,
	udp_port_q,
	mc_port_q,
	ctrl_port_q,
};

extern tPPP_PORT				ppp_ports[MAX_USER];
extern struct rte_mempool 		*direct_pool[PORT_AMOUNT], *indirect_pool[PORT_AMOUNT];
extern struct rte_ring 			*rte_ring;
extern struct rte_ring 			/**decap_udp, *decap_tcp, *encap_udp, *encap_tcp,*/ /**ds_mc_queue, *us_mc_queue,*/ *rg_func_queue;
extern rte_atomic16_t			cp_recv_cums;
uint8_t 						cp_recv_prod;
extern uint8_t					vendor_id;

static uint16_t 				nb_rxd = RX_RING_SIZE;
static uint16_t 				nb_txd = TX_RING_SIZE;

static struct rte_eth_conf port_conf_default = {
	.rxmode = { .max_rx_pkt_len = RTE_ETHER_MAX_LEN, }, 
	.txmode = { .offloads = DEV_TX_OFFLOAD_IPV4_CKSUM | 
							DEV_TX_OFFLOAD_UDP_CKSUM | 
							DEV_TX_OFFLOAD_TCP_CKSUM, },
	.intr_conf = {
        .lsc = 1, /**< link status interrupt feature enabled */ },
};
extern uint16_t 	get_checksum(const void *const addr, const size_t bytes);
extern STATUS 		PPP_FSM(struct rte_timer *ppp, tPPP_PORT *port_ccb, U16 event);
int 				PPP_PORT_INIT(uint16_t port);
int 				ppp_recvd(void);
int 				encapsulation_udp(void);
int 				encapsulation_tcp(void);
int 				control_plane_dequeue(tPPP_MBX **mail);
int 				decapsulation_udp(void);
int 				decapsulation_tcp(void);
void 				decaps_tcp(struct rte_mbuf *single_pkt);
void 				decaps_udp(struct rte_mbuf *single_pkt);
void 				encaps_tcp(struct rte_mbuf *single_pkt);
void 				encaps_udp(struct rte_mbuf *single_pkt);
int 				gateway(void);
void 				drv_xmit(U8 *mu, U16 mulen);
static int			lsi_event_callback(uint16_t port_id, enum rte_eth_event_type type, void *param);

int PPP_PORT_INIT(uint16_t port/*, uint32_t lcore_id*/)
{
	struct rte_eth_conf port_conf = port_conf_default;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_rxconf rxq_conf;
	struct rte_eth_txconf *txconf;
	const uint16_t rx_rings = 1, tx_rings = 5;
	int retval, socket;
	uint16_t q;

	if (vendor_id > VMXNET3)
		port_conf.intr_conf.lsc = 0;
	if (!rte_eth_dev_is_valid_port(port))
		return -1;
	int ret = rte_eth_dev_info_get(port, &dev_info);
	if (ret != 0)
		rte_exit(EXIT_FAILURE, "Error during getting device (port %u) info: %s\n", port, strerror(-ret));
	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |= DEV_TX_OFFLOAD_MBUF_FAST_FREE;

	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;
	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd,&nb_txd);
	if (retval < 0)
		rte_exit(EXIT_FAILURE,"Cannot adjust number of descriptors: err=%d, ""port=%d\n", retval, port);

	rte_eth_dev_callback_register(port, RTE_ETH_EVENT_INTR_LSC, (rte_eth_dev_cb_fn)lsi_event_callback, NULL);

	/*socket = (int) rte_lcore_to_socket_id(lcore_id);
	if (socket == SOCKET_ID_ANY)
		socket = 0;*/

	rxq_conf = dev_info.default_rxconf;
	rxq_conf.offloads = port_conf.rxmode.offloads;
	/* Allocate and set up 1 RX queue per Ethernet port. */
	for(q=0; q<rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd, rte_eth_dev_socket_id(port), &rxq_conf, direct_pool[port]);
		if (retval < 0)
			return retval;
	}

	txconf = &dev_info.default_txconf;
	txconf->offloads = port_conf.txmode.offloads;
	/* Allocate and set up 5 TX queue per Ethernet port. */
	for(q=0; q<tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd, rte_eth_dev_socket_id(port), txconf);
		if (retval < 0)
			return retval;
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;
	rte_eth_promiscuous_enable(port);
	return 0;
}

int ppp_recvd(void)
{
	struct rte_mbuf 	*single_pkt;
	uint64_t 			total_tx;
	struct rte_ether_hdr *eth_hdr, tmp_eth_hdr;
	vlan_header_t		*vlan_header, tmp_vlan_header;
	struct rte_ipv4_hdr *ip_hdr;
	struct rte_icmp_hdr	*icmphdr;
	struct rte_mbuf 	*pkt[BURST_SIZE];
	uint16_t 			ori_port_id, nb_rx;
	ppp_payload_t 		*ppp_payload;
	tPPP_MBX 			*mail = rte_malloc(NULL,sizeof(tPPP_MBX)*32,65536);
	int 				i;
	uint32_t 			icmp_new_cksum;
	char 				*cur;
	uint16_t 			user_index;
	
	usleep(500000);
	for(;;) {
		nb_rx = rte_eth_rx_burst(1, gen_port_q, pkt, BURST_SIZE);
		if (nb_rx == 0)
			continue;
		total_tx = 0;
		for(i=0; i<nb_rx; i++) {
			single_pkt = pkt[i];
			rte_prefetch0(rte_pktmbuf_mtod(single_pkt, void *));
			eth_hdr = rte_pktmbuf_mtod(single_pkt,struct rte_ether_hdr *);
			if (unlikely(eth_hdr->ether_type != rte_cpu_to_be_16(VLAN))) {
				rte_pktmbuf_free(single_pkt);
				continue;
			}
			vlan_header = (vlan_header_t *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct rte_ether_hdr));
			/* We need to detect IGMP and multicast msg here */
			if (unlikely(vlan_header->next_proto != rte_cpu_to_be_16(ETH_P_PPP_SES) && vlan_header->next_proto != rte_cpu_to_be_16(ETH_P_PPP_DIS))) {
				if (vlan_header->next_proto == rte_cpu_to_be_16(FRAME_TYPE_IP)) {
					user_index = (rte_be_to_cpu_16(vlan_header->tci_union.tci_value) & 0xFFF) - 2;
					//uint16_t vlan_id = rte_be_to_cpu_16(vlan_header->tci_union.tci_value) & 0xFFF;
					ip_hdr = (struct rte_ipv4_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t));
					if (ip_hdr->next_proto_id == PROTO_TYPE_UDP) { //use 4001 vlan tag to detect IPTV and VOD packet
						uint16_t vlan_id = rte_be_to_cpu_16(vlan_header->tci_union.tci_value) & 0xFFF;
						if (likely(vlan_id == MULTICAST_TAG || ((ip_hdr->dst_addr) & 0xFFFFFF00) == 10)) // VOD pkt dst ip is always 10.x.x.x
							pkt[total_tx++] = single_pkt;
						else
							rte_pktmbuf_free(single_pkt);
						continue;
					}
					if (ip_hdr->next_proto_id == IPPROTO_IGMP) {
						pkt[total_tx++] = single_pkt;
						continue;
					}
				}
				rte_pktmbuf_free(single_pkt);
				continue;
			}
			ppp_payload = ((ppp_payload_t *)((char *)eth_hdr + sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t) + sizeof(pppoe_header_t)));
			if (unlikely(vlan_header->next_proto == rte_cpu_to_be_16(ETH_P_PPP_DIS) || (ppp_payload->ppp_protocol == rte_cpu_to_be_16(LCP_PROTOCOL) || ppp_payload->ppp_protocol == rte_cpu_to_be_16(AUTH_PROTOCOL) || ppp_payload->ppp_protocol == rte_cpu_to_be_16(IPCP_PROTOCOL)))) {
				/* We need to maintain our ring queue */
				if (rte_atomic16_read(&cp_recv_cums) != ((cp_recv_prod + 1) % 32)) {
					rte_memcpy((mail+cp_recv_prod)->refp,eth_hdr,single_pkt->data_len);
					(mail + cp_recv_prod)->type = IPC_EV_TYPE_DRV;
					(mail + cp_recv_prod)->len = single_pkt->data_len;
					//enqueue eth_hdr single_pkt->data_len
					cur = (char *)(mail + cp_recv_prod);
					rte_ring_enqueue_burst(rte_ring,(void **)&cur,1,NULL);
					cp_recv_prod++;
					if (cp_recv_prod >= 32)
						cp_recv_prod = 0;
				}
				rte_pktmbuf_free(single_pkt);
				continue;
			}
			vlan_header->next_proto = rte_cpu_to_be_16(FRAME_TYPE_IP);
			rte_memcpy(&tmp_eth_hdr,eth_hdr,sizeof(struct rte_ether_hdr));
			rte_memcpy(&tmp_vlan_header,vlan_header,sizeof(struct rte_ether_hdr));
			rte_memcpy((char *)eth_hdr+8,&tmp_eth_hdr,sizeof(struct rte_ether_hdr));
			rte_memcpy((char *)vlan_header+8,&tmp_vlan_header,sizeof(vlan_header_t));
			single_pkt->data_off += 8;
			single_pkt->pkt_len -= 8;
			single_pkt->data_len -= 8;
			eth_hdr = (struct rte_ether_hdr *)((char *)eth_hdr + 8);
			vlan_header = (vlan_header_t *)(eth_hdr + 1);
			user_index = (rte_be_to_cpu_16(vlan_header->tci_union.tci_value) & 0xFFF) - 2;
			ip_hdr = (struct rte_ipv4_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t));
			single_pkt->l2_len = sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t);
			single_pkt->l3_len = sizeof(struct rte_ipv4_hdr);
			switch(ip_hdr->next_proto_id) {
				case PROTO_TYPE_ICMP:
					icmphdr = (struct rte_icmp_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t) + sizeof(struct rte_ipv4_hdr));
					if (icmphdr->icmp_type != 0) {
						rte_pktmbuf_free(single_pkt);
						continue;
					}
					//single_pkt->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM;
					ori_port_id = rte_cpu_to_be_16(icmphdr->icmp_ident);
					int16_t icmp_cksum_diff = icmphdr->icmp_ident - ppp_ports[user_index].addr_table[ori_port_id].port_id;
					rte_memcpy(eth_hdr->s_addr.addr_bytes,ppp_ports[user_index].lan_mac,ETH_ALEN);
					rte_memcpy(eth_hdr->d_addr.addr_bytes,ppp_ports[user_index].addr_table[ori_port_id].mac_addr,ETH_ALEN);
					ip_hdr->dst_addr = ppp_ports[user_index].addr_table[ori_port_id].src_ip;
					icmphdr->icmp_ident = ppp_ports[user_index].addr_table[ori_port_id].port_id;
					ppp_ports[user_index].addr_table[ori_port_id].is_alive = 10;

					if (((icmp_new_cksum = icmp_cksum_diff + icmphdr->icmp_cksum) >> 16) != 0)
						icmp_new_cksum = (icmp_new_cksum & 0xFFFF) + (icmp_new_cksum >> 16);
					icmphdr->icmp_cksum = (uint16_t)icmp_new_cksum;
					ip_hdr->hdr_checksum = 0;
					ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);
					#ifdef _DP_DBG
					puts("nat mapping at port 1");
					#endif
					break;
				case PROTO_TYPE_UDP:
					//rte_ring_enqueue_burst(decap_udp,(void **)&single_pkt,1,NULL);
					decaps_udp(single_pkt);
					//pkt[total_tx++] = single_pkt;
					//rte_pktmbuf_free(single_pkt);
					break;
				case PROTO_TYPE_TCP:
					//rte_ring_enqueue_burst(decap_tcp,(void **)&single_pkt,1,NULL);
					decaps_tcp(single_pkt);
					//pkt[total_tx++] = single_pkt;
					//rte_pktmbuf_free(single_pkt);
					break;
				default:
					rte_pktmbuf_free(single_pkt);
					break;
			}
			pkt[total_tx++] = single_pkt;
		}
		if (likely(total_tx > 0)) {
			uint16_t nb_tx = rte_eth_tx_burst(0, gen_port_q, pkt, total_tx);
			if (unlikely(nb_tx < total_tx)) {
				for(uint16_t buf=nb_tx; buf<total_tx; buf++)
					rte_pktmbuf_free(pkt[buf]);
			}
		}
	}
	return 0;
}
#if 0
int ds_mc(void)
{
	struct rte_mbuf 	*pkt[BURST_SIZE], *single_pkt;
	uint64_t 			total_tx;
	uint16_t			burst_size;
	struct rte_ipv4_hdr *ip_hdr;
	vlan_header_t		*vlan_header;
	int 				i;
	
	for(i=0; i<BURST_SIZE; i++)
		pkt[i] = rte_pktmbuf_alloc(mbuf_pool);

	for(;;) {
		burst_size = rte_ring_dequeue_burst(ds_mc_queue,(void **)pkt,BURST_SIZE,NULL);
		if (unlikely(burst_size == 0))
			continue;
		total_tx = 0;
		for(i=0; i<burst_size; i++) {
			single_pkt = pkt[i];
			rte_prefetch0(rte_pktmbuf_mtod(single_pkt, void *));
			/* Need to check whether the packet is multicast or VOD */
			vlan_header = (vlan_header_t *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct rte_ether_hdr));
			uint16_t vlan_id = rte_be_to_cpu_16(vlan_header->tci_union.tci_value) & 0xFFF;
			ip_hdr = (struct rte_ipv4_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t));
			if (likely(vlan_id == MULTICAST_TAG || ((ip_hdr->dst_addr) & 0xFFFFFF00) == 10)) // VOD pkt dst ip is always 10.x.x.x
				pkt[total_tx++] = single_pkt;
			//else
				//rte_pktmbuf_free(single_pkt);
		}
		if (likely(total_tx > 0)) {
			uint16_t nb_tx = rte_eth_tx_burst(0, mc_port_q, pkt, total_tx);
			if (unlikely(nb_tx < total_tx)) {
				for(uint16_t buf=nb_tx; buf<total_tx; buf++)
					rte_pktmbuf_free(pkt[buf]);
			}
		}
	}
	return 0;
}
#endif

void decaps_udp(struct rte_mbuf *single_pkt)
{
	struct rte_ether_hdr *eth_hdr;
	vlan_header_t		*vlan_header;
	struct rte_ipv4_hdr *ip_hdr;
	struct rte_udp_hdr 	*udphdr;
	uint16_t 			ori_port_id, user_index;

	rte_prefetch0(rte_pktmbuf_mtod(single_pkt, void *));
	eth_hdr = rte_pktmbuf_mtod(single_pkt, struct rte_ether_hdr*);
	vlan_header = (vlan_header_t *)(eth_hdr + 1);
	user_index = (rte_be_to_cpu_16(vlan_header->tci_union.tci_value) & 0xFFF) - 2;
	/* for NAT mapping */
	ip_hdr = (struct rte_ipv4_hdr *)(rte_pktmbuf_mtod(single_pkt,unsigned char *) + sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t));
	ip_hdr->hdr_checksum = 0;

	//single_pkt->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM/* | PKT_TX_UDP_CKSUM*/;
	udphdr = (struct rte_udp_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t) + sizeof(struct rte_ipv4_hdr));
	ori_port_id = rte_cpu_to_be_16(udphdr->dst_port);
	rte_memcpy(eth_hdr->s_addr.addr_bytes,ppp_ports[user_index].lan_mac,ETH_ALEN);
	rte_memcpy(eth_hdr->d_addr.addr_bytes,ppp_ports[user_index].addr_table[ori_port_id].mac_addr,ETH_ALEN);
	ip_hdr->dst_addr = ppp_ports[user_index].addr_table[ori_port_id].src_ip;
	udphdr->dst_port = ppp_ports[user_index].addr_table[ori_port_id].port_id;
	ppp_ports[user_index].addr_table[ori_port_id].is_alive = 10;
	ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);
	udphdr->dgram_cksum = 0;
	udphdr->dgram_cksum = rte_ipv4_udptcp_cksum(ip_hdr,udphdr);
}
#if 0
int decapsulation_udp(void)
{
	uint64_t 			total_tx;
	struct rte_ether_hdr 	*eth_hdr;
	vlan_header_t		*vlan_header;
	struct rte_ipv4_hdr 	*ip_hdr;
	struct rte_udp_hdr 		*udphdr;
	uint16_t 			ori_port_id, burst_size, user_index;
	struct rte_mbuf 	*pkt[BURST_SIZE], *single_pkt;
	int 				i;
	
	for(i=0; i<BURST_SIZE; i++)
		pkt[i] = rte_pktmbuf_alloc(mbuf_pool);

	for(;;) {
		burst_size = rte_ring_dequeue_burst(decap_udp,(void **)pkt,BURST_SIZE,NULL);
		if (unlikely(burst_size == 0))
			continue;
		total_tx = 0;
		for(i=0; i<burst_size; i++) {
			single_pkt = pkt[i];
			rte_prefetch0(rte_pktmbuf_mtod(single_pkt,void *));
			eth_hdr = rte_pktmbuf_mtod(single_pkt,struct rte_ether_hdr*);
			vlan_header = (vlan_header_t *)(eth_hdr + 1);
			user_index = (rte_be_to_cpu_16(vlan_header->tci_union.tci_value) & 0xFFF) - 2;
			/* for NAT mapping */
			ip_hdr = (struct rte_ipv4_hdr *)(rte_pktmbuf_mtod(single_pkt,unsigned char *) + sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t));
			ip_hdr->hdr_checksum = 0;

			single_pkt->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM/* | PKT_TX_UDP_CKSUM*/;
			udphdr = (struct rte_udp_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t) + sizeof(struct rte_ipv4_hdr));
			ori_port_id = rte_cpu_to_be_16(udphdr->dst_port);
			rte_memcpy(eth_hdr->s_addr.addr_bytes,ppp_ports[user_index].lan_mac,ETH_ALEN);
			rte_memcpy(eth_hdr->d_addr.addr_bytes,ppp_ports[user_index].addr_table[ori_port_id].mac_addr,ETH_ALEN);
			ip_hdr->dst_addr = ppp_ports[user_index].addr_table[ori_port_id].src_ip;
			udphdr->dst_port = ppp_ports[user_index].addr_table[ori_port_id].port_id;
			ppp_ports[user_index].addr_table[ori_port_id].is_alive = 10;

			udphdr->dgram_cksum = 0;
			udphdr->dgram_cksum = rte_ipv4_udptcp_cksum(ip_hdr,udphdr);

			pkt[total_tx++] = single_pkt;
		}
		if (likely(total_tx > 0))
			rte_eth_tx_burst(0, udp_port_q, pkt, total_tx);
	}
	return 0;
}
#endif
void decaps_tcp(struct rte_mbuf *single_pkt)
{
	struct rte_ether_hdr *eth_hdr;
	vlan_header_t		*vlan_header;
	struct rte_ipv4_hdr *ip_hdr;
	struct rte_tcp_hdr 	*tcphdr;
	uint16_t 			ori_port_id, user_index;
	
	rte_prefetch0(rte_pktmbuf_mtod(single_pkt,void *));
	eth_hdr = rte_pktmbuf_mtod(single_pkt,struct rte_ether_hdr*);
	vlan_header = (vlan_header_t *)(eth_hdr + 1);
	user_index = (rte_be_to_cpu_16(vlan_header->tci_union.tci_value) & 0xFFF) - 2;
	/* for NAT mapping */
	ip_hdr = (struct rte_ipv4_hdr *)(rte_pktmbuf_mtod(single_pkt,unsigned char *) + sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t));
	ip_hdr->hdr_checksum = 0;

	//single_pkt->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM/* | PKT_TX_TCP_CKSUM*/;
	tcphdr = (struct rte_tcp_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t) + sizeof(struct rte_ipv4_hdr));
	ori_port_id = rte_cpu_to_be_16(tcphdr->dst_port);
	rte_memcpy(eth_hdr->s_addr.addr_bytes,ppp_ports[user_index].lan_mac,ETH_ALEN);
	rte_memcpy(eth_hdr->d_addr.addr_bytes,ppp_ports[user_index].addr_table[ori_port_id].mac_addr,ETH_ALEN);
	ip_hdr->dst_addr = ppp_ports[user_index].addr_table[ori_port_id].src_ip;
	tcphdr->dst_port = ppp_ports[user_index].addr_table[ori_port_id].port_id;
	ppp_ports[user_index].addr_table[ori_port_id].is_alive = 10;
	ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);
	tcphdr->cksum = 0;
	tcphdr->cksum = rte_ipv4_udptcp_cksum(ip_hdr,tcphdr);
}
#if 0
int decapsulation_tcp(void)
{
	uint64_t 			total_tx;
	struct rte_ether_hdr *eth_hdr;
	vlan_header_t		*vlan_header;
	struct rte_ipv4_hdr *ip_hdr;
	struct rte_tcp_hdr 	*tcphdr;
	uint16_t 			ori_port_id, burst_size, user_index;
	struct rte_mbuf 	*pkt[BURST_SIZE], *single_pkt;
	int 				i;
	
	for(i=0; i<BURST_SIZE; i++)
		pkt[i] = rte_pktmbuf_alloc(mbuf_pool);

	for(;;) {
		burst_size = rte_ring_dequeue_burst(decap_tcp,(void **)pkt,BURST_SIZE,NULL);
		if (unlikely(burst_size == 0))
			continue;
		total_tx = 0;
		for(i=0; i<burst_size; i++) {
			single_pkt = pkt[i];
			rte_prefetch0(rte_pktmbuf_mtod(single_pkt,void *));
			eth_hdr = rte_pktmbuf_mtod(single_pkt,struct rte_ether_hdr*);
			vlan_header = (vlan_header_t *)(eth_hdr + 1);
			user_index = (rte_be_to_cpu_16(vlan_header->tci_union.tci_value) & 0xFFF) - 2;
			/* for NAT mapping */
			ip_hdr = (struct rte_ipv4_hdr *)(rte_pktmbuf_mtod(single_pkt,unsigned char *) + sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t));
			ip_hdr->hdr_checksum = 0;

			single_pkt->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM/* | PKT_TX_TCP_CKSUM*/;
			tcphdr = (struct rte_tcp_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t) + sizeof(struct rte_ipv4_hdr));
			ori_port_id = rte_cpu_to_be_16(tcphdr->dst_port);
			rte_memcpy(eth_hdr->s_addr.addr_bytes,ppp_ports[user_index].lan_mac,ETH_ALEN);
			rte_memcpy(eth_hdr->d_addr.addr_bytes,ppp_ports[user_index].addr_table[ori_port_id].mac_addr,ETH_ALEN);
			ip_hdr->dst_addr = ppp_ports[user_index].addr_table[ori_port_id].src_ip;
			tcphdr->dst_port = ppp_ports[user_index].addr_table[ori_port_id].port_id;
			ppp_ports[user_index].addr_table[ori_port_id].is_alive = 10;
			tcphdr->cksum = 0;
			tcphdr->cksum = rte_ipv4_udptcp_cksum(ip_hdr,tcphdr);

			pkt[total_tx++] = single_pkt;
		}
		if (likely(total_tx > 0))
			rte_eth_tx_burst(0, tcp_port_q, pkt, total_tx);
	}
	return 0;
}
#endif
int control_plane_dequeue(tPPP_MBX **mail)
{
	uint16_t burst_size;

	for(;;) {
		burst_size = rte_ring_dequeue_burst(rte_ring,(void **)mail,BURST_SIZE,NULL);
		if (likely(burst_size == 0))
			continue;
		break;
	}
	return burst_size;
}

void encaps_udp(struct rte_mbuf *single_pkt)
{
	struct rte_udp_hdr 	*udphdr;
	char 				*cur;
	uint32_t 			new_port_id;
	pppoe_header_t 		*pppoe_header;
	uint16_t			user_index;
	struct rte_ether_hdr *eth_hdr;
	vlan_header_t		*vlan_header;
	struct rte_ipv4_hdr *ip_hdr;

	rte_prefetch0(rte_pktmbuf_mtod(single_pkt,void *));
	eth_hdr = rte_pktmbuf_mtod(single_pkt,struct rte_ether_hdr*);
	vlan_header = (vlan_header_t *)(eth_hdr + 1);
	user_index = (rte_be_to_cpu_16(vlan_header->tci_union.tci_value) & 0xFFF) - 2;
	ip_hdr = (struct rte_ipv4_hdr *)(rte_pktmbuf_mtod(single_pkt,unsigned char *) + sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t));
	ip_hdr->hdr_checksum = 0;
			
	/* for nat */
	//single_pkt->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_UDP_CKSUM;

	udphdr = (struct rte_udp_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t) + sizeof(struct rte_ipv4_hdr));
	nat_udp_learning(eth_hdr,ip_hdr,udphdr,&new_port_id,ppp_ports[user_index].addr_table);
	ip_hdr->src_addr = ppp_ports[user_index].ipv4;
	udphdr->src_port = rte_cpu_to_be_16(new_port_id);
	ppp_ports[user_index].addr_table[new_port_id].is_alive = 10;
	ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);
	udphdr->dgram_cksum = 0;
	udphdr->dgram_cksum = rte_ipv4_udptcp_cksum(ip_hdr,udphdr);

	/* for PPPoE */
	rte_memcpy(eth_hdr->s_addr.addr_bytes,ppp_ports[user_index].src_mac,ETH_ALEN);
	rte_memcpy(eth_hdr->d_addr.addr_bytes,ppp_ports[user_index].dst_mac,ETH_ALEN);

	vlan_header->next_proto = rte_cpu_to_be_16(ETH_P_PPP_SES);
	cur = (char *)eth_hdr - 8;
	rte_memcpy(cur,eth_hdr,sizeof(struct rte_ether_hdr));
	rte_memcpy(cur+sizeof(struct rte_ether_hdr),vlan_header,sizeof(vlan_header_t));
	pppoe_header = (pppoe_header_t *)(cur+sizeof(struct rte_ether_hdr)+sizeof(vlan_header_t));
	pppoe_header->ver_type = VER_TYPE;
	pppoe_header->code = 0;
	pppoe_header->session_id = ppp_ports[user_index].session_id;
	pppoe_header->length = rte_cpu_to_be_16((single_pkt->pkt_len) - 18 + 2);
	*((uint16_t *)(cur+sizeof(struct rte_ether_hdr)+sizeof(vlan_header_t)+sizeof(pppoe_header_t))) = rte_cpu_to_be_16(IP_PROTOCOL);
	single_pkt->data_off -= 8;
	single_pkt->pkt_len += 8;
	single_pkt->data_len += 8;
}
#if 0
int encapsulation_udp(void)
{
	struct rte_udp_hdr 	*udphdr;
	char 				*cur;
	uint32_t 			new_port_id;
	pppoe_header_t 		*pppoe_header;
	struct rte_mbuf 	*pkt[BURST_SIZE], *single_pkt;
	uint64_t 			total_tx;
	uint16_t			burst_size, user_index;
	struct rte_ether_hdr *eth_hdr;
	vlan_header_t		*vlan_header;
	struct rte_ipv4_hdr *ip_hdr;
	int 				i;

	for(i=0; i<BURST_SIZE; i++)
		pkt[i] = rte_pktmbuf_alloc(mbuf_pool);

	for(;;) {
		burst_size = rte_ring_dequeue_burst(encap_udp,(void **)pkt,BURST_SIZE,NULL);
		if (unlikely(burst_size == 0))
			continue;
		total_tx = 0;
		for(i=0; i<burst_size; i++) {
			single_pkt = pkt[i];
			rte_prefetch0(rte_pktmbuf_mtod(single_pkt,void *));
			eth_hdr = rte_pktmbuf_mtod(single_pkt,struct rte_ether_hdr*);
			vlan_header = (vlan_header_t *)(eth_hdr + 1);
			user_index = (rte_be_to_cpu_16(vlan_header->tci_union.tci_value) & 0xFFF) - 2;
			ip_hdr = (struct rte_ipv4_hdr *)(rte_pktmbuf_mtod(single_pkt,unsigned char *) + sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t));
			ip_hdr->hdr_checksum = 0;
			
			/* for nat */
			//single_pkt->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_UDP_CKSUM;

			udphdr = (struct rte_udp_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t) + sizeof(struct rte_ipv4_hdr));
			nat_udp_learning(eth_hdr,ip_hdr,udphdr,&new_port_id,ppp_ports[user_index].addr_table);
			ip_hdr->src_addr = ppp_ports[user_index].ipv4;
			udphdr->src_port = rte_cpu_to_be_16(new_port_id);
			ppp_ports[user_index].addr_table[new_port_id].is_alive = 10;
			ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);
			udphdr->dgram_cksum = 0;
			udphdr->dgram_cksum = rte_ipv4_udptcp_cksum(ip_hdr,udphdr);

			/* for PPPoE */
			rte_memcpy(eth_hdr->s_addr.addr_bytes,ppp_ports[user_index].src_mac,ETH_ALEN);
			rte_memcpy(eth_hdr->d_addr.addr_bytes,ppp_ports[user_index].dst_mac,ETH_ALEN);

			vlan_header->next_proto = rte_cpu_to_be_16(ETH_P_PPP_SES);
			cur = (char *)eth_hdr - 8;
			rte_memcpy(cur,eth_hdr,sizeof(struct rte_ether_hdr));
			rte_memcpy(cur+sizeof(struct rte_ether_hdr),vlan_header,sizeof(vlan_header_t));
			pppoe_header = (pppoe_header_t *)(cur+sizeof(struct rte_ether_hdr)+sizeof(vlan_header_t));
			pppoe_header->ver_type = 0x11;
			pppoe_header->code = 0;
			pppoe_header->session_id = ppp_ports[user_index].session_id;
			pppoe_header->length = rte_cpu_to_be_16((single_pkt->pkt_len) - 18 + 2);
			*((uint16_t *)(cur+sizeof(struct rte_ether_hdr)+sizeof(vlan_header_t)+sizeof(pppoe_header_t))) = rte_cpu_to_be_16(IP_PROTOCOL);
			single_pkt->data_off -= 8;
			single_pkt->pkt_len += 8;
			single_pkt->data_len += 8;

			pkt[total_tx++] = single_pkt;
		}
		if (likely(total_tx > 0))
			rte_eth_tx_burst(1, udp_port_q, pkt, total_tx);
	}
	return 0;
}
#endif
void encaps_tcp(struct rte_mbuf *single_pkt)
{
	struct rte_tcp_hdr 	*tcphdr;
	char 				*cur;
	uint32_t 			new_port_id;
	pppoe_header_t 		*pppoe_header;
	uint16_t			user_index;
	struct rte_ether_hdr *eth_hdr;
	vlan_header_t		*vlan_header;
	struct rte_ipv4_hdr *ip_hdr;

	rte_prefetch0(rte_pktmbuf_mtod(single_pkt,void *));
	eth_hdr = rte_pktmbuf_mtod(single_pkt,struct rte_ether_hdr*);
	vlan_header = (vlan_header_t *)(eth_hdr + 1);
	user_index = (rte_be_to_cpu_16(vlan_header->tci_union.tci_value) & 0xFFF) - 2;
	ip_hdr = (struct rte_ipv4_hdr *)(rte_pktmbuf_mtod(single_pkt,unsigned char *) + sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t));
	ip_hdr->hdr_checksum = 0;
	/* for nat */
	//single_pkt->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_TCP_CKSUM;

	tcphdr = (struct rte_tcp_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t) + sizeof(struct rte_ipv4_hdr));
	nat_tcp_learning(eth_hdr,ip_hdr,tcphdr,&new_port_id,ppp_ports[user_index].addr_table);
	ip_hdr->src_addr = ppp_ports[user_index].ipv4;
	tcphdr->src_port = rte_cpu_to_be_16(new_port_id);
	ppp_ports[user_index].addr_table[new_port_id].is_alive = 10;
	ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);
	tcphdr->cksum = 0;
	tcphdr->cksum = rte_ipv4_udptcp_cksum(ip_hdr,tcphdr);

	/* for PPPoE */
	rte_memcpy(eth_hdr->s_addr.addr_bytes,ppp_ports[user_index].src_mac,ETH_ALEN);
	rte_memcpy(eth_hdr->d_addr.addr_bytes,ppp_ports[user_index].dst_mac,ETH_ALEN);

	vlan_header->next_proto = rte_cpu_to_be_16(ETH_P_PPP_SES);
	cur = (char *)eth_hdr - 8;
	rte_memcpy(cur,eth_hdr,sizeof(struct rte_ether_hdr));
	rte_memcpy(cur+sizeof(struct rte_ether_hdr),vlan_header,sizeof(vlan_header_t));
	pppoe_header = (pppoe_header_t *)(cur+sizeof(struct rte_ether_hdr)+sizeof(vlan_header_t));
	pppoe_header->ver_type = VER_TYPE;
	pppoe_header->code = 0;
	pppoe_header->session_id = ppp_ports[user_index].session_id;
	pppoe_header->length = rte_cpu_to_be_16((single_pkt->pkt_len) - 18 + 2);
	*((uint16_t *)(cur+sizeof(struct rte_ether_hdr)+sizeof(vlan_header_t)+sizeof(pppoe_header_t))) = rte_cpu_to_be_16(IP_PROTOCOL);
	single_pkt->data_off -= 8;
	single_pkt->pkt_len += 8;
	single_pkt->data_len += 8;
}
#if 0
int encapsulation_tcp(void)
{
	struct rte_tcp_hdr 	*tcphdr;
	char 				*cur;
	uint32_t 			new_port_id;
	pppoe_header_t 		*pppoe_header;
	struct rte_mbuf 	*pkt[BURST_SIZE], *single_pkt;
	uint64_t 			total_tx;
	uint16_t			burst_size, user_index;
	struct rte_ether_hdr *eth_hdr;
	vlan_header_t		*vlan_header;
	struct rte_ipv4_hdr *ip_hdr;
	int 				i;
	
	for(i=0; i<BURST_SIZE; i++)
		pkt[i] = rte_pktmbuf_alloc(mbuf_pool);

	for(;;) {
		burst_size = rte_ring_dequeue_burst(encap_tcp,(void **)pkt,BURST_SIZE,NULL);
		if (unlikely(burst_size == 0))
			continue;
		total_tx = 0;
		for(i=0; i<burst_size; i++) {
			single_pkt = pkt[i];
			rte_prefetch0(rte_pktmbuf_mtod(single_pkt,void *));
			eth_hdr = rte_pktmbuf_mtod(single_pkt,struct rte_ether_hdr*);
			vlan_header = (vlan_header_t *)(eth_hdr + 1);
			user_index = (rte_be_to_cpu_16(vlan_header->tci_union.tci_value) & 0xFFF) - 2;
			ip_hdr = (struct rte_ipv4_hdr *)(rte_pktmbuf_mtod(single_pkt,unsigned char *) + sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t));
			ip_hdr->hdr_checksum = 0;
			/* for nat */
			//single_pkt->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_TCP_CKSUM;

			tcphdr = (struct rte_tcp_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t) + sizeof(struct rte_ipv4_hdr));
			nat_tcp_learning(eth_hdr,ip_hdr,tcphdr,&new_port_id,ppp_ports[user_index].addr_table);
			ip_hdr->src_addr = ppp_ports[user_index].ipv4;
			tcphdr->src_port = rte_cpu_to_be_16(new_port_id);
			ppp_ports[user_index].addr_table[new_port_id].is_alive = 10;
			ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);
			tcphdr->cksum = 0;
			tcphdr->cksum = rte_ipv4_udptcp_cksum(ip_hdr,tcphdr);

			/* for PPPoE */
			rte_memcpy(eth_hdr->s_addr.addr_bytes,ppp_ports[user_index].src_mac,ETH_ALEN);
			rte_memcpy(eth_hdr->d_addr.addr_bytes,ppp_ports[user_index].dst_mac,ETH_ALEN);

			vlan_header->next_proto = rte_cpu_to_be_16(ETH_P_PPP_SES);
			cur = (char *)eth_hdr - 8;
			rte_memcpy(cur,eth_hdr,sizeof(struct rte_ether_hdr));
			rte_memcpy(cur+sizeof(struct rte_ether_hdr),vlan_header,sizeof(vlan_header_t));
			pppoe_header = (pppoe_header_t *)(cur+sizeof(struct rte_ether_hdr)+sizeof(vlan_header_t));
			pppoe_header->ver_type = 0x11;
			pppoe_header->code = 0;
			pppoe_header->session_id = ppp_ports[user_index].session_id;
			pppoe_header->length = rte_cpu_to_be_16((single_pkt->pkt_len) - 18 + 2);
			*((uint16_t *)(cur+sizeof(struct rte_ether_hdr)+sizeof(vlan_header_t)+sizeof(pppoe_header_t))) = rte_cpu_to_be_16(IP_PROTOCOL);
			single_pkt->data_off -= 8;
			single_pkt->pkt_len += 8;
			single_pkt->data_len += 8;

			pkt[total_tx++] = single_pkt;
		}
		if (likely(total_tx > 0))
			rte_eth_tx_burst(1, tcp_port_q, pkt, total_tx);
	}
	return 0;
}
#endif
#if 0
int us_mc(void)
{
	struct rte_mbuf 	*pkt[BURST_SIZE], *single_pkt;
	uint64_t 			total_tx;
	uint16_t			burst_size;
	int 				i;
	
	for(i=0; i<BURST_SIZE; i++)
		pkt[i] = rte_pktmbuf_alloc(mbuf_pool);

	for(;;) {
		burst_size = rte_ring_dequeue_burst(us_mc_queue,(void **)pkt,BURST_SIZE,NULL);
		if (unlikely(burst_size == 0))
			continue;
		total_tx = 0;
		for(i=0; i<burst_size; i++) {
			single_pkt = pkt[i];
			/* Need to check whether the packet is multicast */
			pkt[total_tx++] = single_pkt;
		}
		if (likely(total_tx > 0))
			rte_eth_tx_burst(1, mc_port_q, pkt, total_tx);
	}
	return 0;
}
#endif
int gateway(void)
{
	struct rte_mbuf 	*single_pkt;
	uint64_t 			total_tx;
	struct rte_ether_hdr *eth_hdr;
	vlan_header_t		*vlan_header;
	struct rte_ipv4_hdr *ip_hdr;
	struct rte_icmp_hdr *icmphdr;
	struct rte_mbuf 	*pkt[BURST_SIZE*2];
	//unsigned char 		mac_addr[6];
	char 				*cur;
	int 				i;
	pppoe_header_t 		*pppoe_header;
	uint16_t 			nb_tx, nb_rx, user_index;
	//uint32_t			lan_ip = rte_cpu_to_be_32(0xc0a80201); //192.168.2.1

	usleep(500000);
	//rte_eth_macaddr_get(0, (struct rte_ether_addr *)mac_addr);
	for(;;) {
		nb_rx = rte_eth_rx_burst(0, gen_port_q, pkt, BURST_SIZE);
		if (nb_rx == 0)
			continue;
		total_tx = 0;
		for(i=0; i<nb_rx; i++) {
			single_pkt = pkt[i];
			rte_prefetch0(rte_pktmbuf_mtod(single_pkt, void *));
			eth_hdr = rte_pktmbuf_mtod(single_pkt, struct rte_ether_hdr*);
			if (unlikely(eth_hdr->ether_type != rte_cpu_to_be_16(VLAN))) {
				rte_pktmbuf_free(single_pkt);
				continue;
			}
			rte_rmb();
			vlan_header = (vlan_header_t *)(eth_hdr + 1);
			/* translate from vlan id to user index, we mention vlan_id - 2 = user_id */
			user_index = (rte_be_to_cpu_16(vlan_header->tci_union.tci_value) & 0xFFF) - 2;
			if (unlikely(user_index > MAX_USER)) {
				rte_pktmbuf_free(single_pkt);
				continue;
			}

			if (unlikely(vlan_header->next_proto == rte_cpu_to_be_16(FRAME_TYPE_ARP))) { 
				/* We only reply arp request to us */
				rte_ring_enqueue_burst(rg_func_queue, (void **)&single_pkt, 1, NULL);
				continue;
			}
			else if (unlikely(vlan_header->next_proto == rte_cpu_to_be_16(ETH_P_PPP_DIS) || (vlan_header->next_proto == rte_cpu_to_be_16(ETH_P_PPP_SES))))
				//pkt[total_tx++] = single_pkt;
				rte_pktmbuf_free(single_pkt);
			else if (likely(vlan_header->next_proto == rte_cpu_to_be_16(FRAME_TYPE_IP))) {
				ip_hdr = (struct rte_ipv4_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t));
				if (unlikely((ip_hdr->src_addr) << 8 != ppp_ports[user_index].lan_ip << 8)) {
					rte_pktmbuf_free(single_pkt);
					continue;
				}
				single_pkt->l2_len = sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t) + sizeof(pppoe_header_t) + sizeof(ppp_payload_t);
				single_pkt->l3_len = sizeof(struct rte_ipv4_hdr);
				
				if (ip_hdr->next_proto_id == PROTO_TYPE_ICMP) {
					//single_pkt->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM;
					icmphdr = (struct rte_icmp_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t) + sizeof(struct rte_ipv4_hdr));
					if (ip_hdr->dst_addr != ppp_ports[user_index].lan_ip) {
						if (unlikely(ppp_ports[user_index].data_plane_start == FALSE)) {
							rte_pktmbuf_free(single_pkt);
							continue;
						}
						uint32_t 			new_port_id;
						uint32_t			icmp_new_cksum;

						nat_icmp_learning(eth_hdr, ip_hdr, icmphdr, &new_port_id, ppp_ports[user_index].addr_table);
						ip_hdr->src_addr = ppp_ports[user_index].ipv4;
						icmphdr->icmp_ident = rte_cpu_to_be_16(new_port_id);
						ppp_ports[user_index].addr_table[new_port_id].is_alive = 10;
						ip_hdr->hdr_checksum = 0;
						ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);

						if (((icmp_new_cksum = icmphdr->icmp_cksum + ppp_ports[user_index].addr_table[new_port_id].port_id - rte_cpu_to_be_16(new_port_id)) >> 16) != 0)
							icmp_new_cksum = (icmp_new_cksum & 0xFFFF) + (icmp_new_cksum >> 16);
						icmphdr->icmp_cksum = (uint16_t)icmp_new_cksum;
						
						rte_memcpy(eth_hdr->s_addr.addr_bytes, ppp_ports[user_index].src_mac, ETH_ALEN);
						rte_memcpy(eth_hdr->d_addr.addr_bytes, ppp_ports[user_index].dst_mac, ETH_ALEN);

						vlan_header->next_proto = rte_cpu_to_be_16(ETH_P_PPP_SES);
						cur = (char *)eth_hdr - 8;
						rte_memcpy(cur, eth_hdr, sizeof(struct rte_ether_hdr));
						rte_memcpy(cur+sizeof(struct rte_ether_hdr), vlan_header, sizeof(vlan_header_t));
						pppoe_header = (pppoe_header_t *)(cur+sizeof(struct rte_ether_hdr)+sizeof(vlan_header_t));
						pppoe_header->ver_type = 0x11;
						pppoe_header->code = 0;
						pppoe_header->session_id = ppp_ports[user_index].session_id;
						pppoe_header->length = rte_cpu_to_be_16((single_pkt->pkt_len) - 18 + 2);
						*((uint16_t *)(cur+sizeof(struct rte_ether_hdr)+sizeof(vlan_header_t)+sizeof(pppoe_header_t))) = rte_cpu_to_be_16(IP_PROTOCOL);
						single_pkt->data_off -= 8;
						single_pkt->pkt_len += 8;
						single_pkt->data_len += 8;
						
						pkt[total_tx++] = single_pkt;
						#ifdef _DP_DBG
						puts("nat icmp at port 0");
						#endif
					}
					else {
						rte_ring_enqueue_burst(rg_func_queue, (void **)&single_pkt, 1, NULL);
						continue;
					}
				}
				else if (ip_hdr->next_proto_id == IPPROTO_IGMP)
					pkt[total_tx++] = single_pkt;
				else if (ip_hdr->next_proto_id == PROTO_TYPE_TCP) {
					if (unlikely(ppp_ports[user_index].data_plane_start == FALSE)) {
						rte_pktmbuf_free(single_pkt);
						continue;
					}
					//rte_ring_enqueue_burst(encap_tcp, (void **)&single_pkt, 1, NULL);
					encaps_tcp(single_pkt);
					pkt[total_tx++] = single_pkt;
				}
				else if (ip_hdr->next_proto_id == PROTO_TYPE_UDP) {
					if (unlikely(ppp_ports[user_index].data_plane_start == FALSE)) {
						rte_pktmbuf_free(single_pkt);
						continue;
					}

					//rte_ring_enqueue_burst(encap_udp, (void **)&single_pkt, 1, NULL);
					encaps_udp(single_pkt);
					pkt[total_tx++] = single_pkt;
				}
				else {
					#ifdef _DP_DBG
					puts("unknown L4 packet recv on gateway LAN port queue");
					printf("protocol = %x\n", ip_hdr->next_proto_id);
					#endif
					rte_pktmbuf_free(single_pkt);
				}
			}
			else {
				#ifdef _DP_DBG
				puts("unknown ether type recv on gateway LAN port queue");
				printf("ether type = %x\n", rte_be_to_cpu_16(eth_hdr->ether_type));
				#endif
				rte_pktmbuf_free(single_pkt);
				continue;
			}
		}
		if (likely(total_tx > 0)) {
			nb_tx = rte_eth_tx_burst(1, gen_port_q, pkt, total_tx);
			if (unlikely(nb_tx < total_tx)) {
				for(uint16_t buf=nb_tx; buf<total_tx; buf++)
					rte_pktmbuf_free(pkt[buf]);
			}
		}
	}
	return 0;
}


/* process RG function such as DHCP server, gateway ARP replying */
int rg_func(void)
{
	/*struct rte_udp_hdr 	*udphdr;
	char 				*cur;
	uint32_t 			new_port_id;
	pppoe_header_t 		*pppoe_header;*/
	struct rte_mbuf 	*pkt[BURST_SIZE], *single_pkt;
	//uint64_t 			total_tx;
	uint16_t			burst_size, user_index;
	struct rte_ether_hdr *eth_hdr;
	vlan_header_t		*vlan_header;
	struct rte_ipv4_hdr *ip_hdr;
	int 				i;
	struct rte_arp_hdr	*arphdr;
	struct rte_icmp_hdr *icmphdr;

	for(i=0; i<BURST_SIZE; i++)
		pkt[i] = rte_pktmbuf_alloc(direct_pool[0]);

	for(;;) {
		burst_size = rte_ring_dequeue_burst(rg_func_queue,(void **)pkt,BURST_SIZE,NULL);
		if (unlikely(burst_size == 0))
			continue;
		//total_tx = 0;
		for(i=0; i<burst_size; i++) {
			single_pkt = pkt[i];
			rte_prefetch0(rte_pktmbuf_mtod(single_pkt, void *));
			eth_hdr = rte_pktmbuf_mtod(single_pkt, struct rte_ether_hdr*);
			vlan_header = (vlan_header_t *)(eth_hdr + 1);
			user_index = (rte_be_to_cpu_16(vlan_header->tci_union.tci_value) & 0xFFF) - 2;
			if (unlikely(vlan_header->next_proto == rte_cpu_to_be_16(FRAME_TYPE_ARP))) {
				arphdr = (struct rte_arp_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t));
				if (arphdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST) && arphdr->arp_data.arp_tip == ppp_ports[user_index].lan_ip) {
					rte_memcpy(eth_hdr->d_addr.addr_bytes,eth_hdr->s_addr.addr_bytes,ETH_ALEN);
					rte_memcpy(eth_hdr->s_addr.addr_bytes,ppp_ports[user_index].lan_mac,ETH_ALEN);
					rte_memcpy(arphdr->arp_data.arp_tha.addr_bytes,arphdr->arp_data.arp_sha.addr_bytes,ETH_ALEN);
					rte_memcpy(arphdr->arp_data.arp_sha.addr_bytes,ppp_ports[user_index].lan_mac,ETH_ALEN);
					arphdr->arp_data.arp_tip = arphdr->arp_data.arp_sip;
					arphdr->arp_data.arp_sip = ppp_ports[user_index].lan_ip;
					arphdr->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
					rte_eth_tx_burst(0, gen_port_q, &single_pkt, 1);
					continue;
				}
				rte_pktmbuf_free(single_pkt);
				continue;
			}
			else if (likely(vlan_header->next_proto == rte_cpu_to_be_16(FRAME_TYPE_IP))) {
				ip_hdr = (struct rte_ipv4_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t));
				if (ip_hdr->next_proto_id == PROTO_TYPE_ICMP) {
					icmphdr = (struct rte_icmp_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t) + sizeof(struct rte_ipv4_hdr));
					if (ip_hdr->dst_addr == ppp_ports[user_index].lan_ip) {
						memcpy(eth_hdr->d_addr.addr_bytes, eth_hdr->s_addr.addr_bytes, ETH_ALEN);
						memcpy(eth_hdr->s_addr.addr_bytes, ppp_ports[user_index].lan_mac, ETH_ALEN);
						ip_hdr->dst_addr = ip_hdr->src_addr;
						ip_hdr->src_addr = ppp_ports[user_index].lan_ip;
						icmphdr->icmp_type = 0;
						uint32_t cksum = ~icmphdr->icmp_cksum & 0xffff;
						cksum += ~rte_cpu_to_be_16(8 << 8) & 0xffff;
						cksum += rte_cpu_to_be_16(0 << 8);
		  				cksum = (cksum & 0xffff) + (cksum >> 16);
						cksum = (cksum & 0xffff) + (cksum >> 16);
						icmphdr->icmp_cksum = ~cksum;
						rte_eth_tx_burst(0, gen_port_q, &single_pkt, 1);
						continue;
					}
					else {
						rte_pktmbuf_free(single_pkt);
						continue;
					}
				}
			}
			else {
				rte_pktmbuf_free(single_pkt);
				continue;
			}
		}
	}
	return 0;
}

void drv_xmit(U8 *mu, U16 mulen)
{
	struct rte_mbuf *pkt;
	char 			*buf;

	pkt = rte_pktmbuf_alloc(direct_pool[0]);
	buf = rte_pktmbuf_mtod(pkt, char *);
	rte_memcpy(buf, mu, mulen);
	pkt->data_len = mulen;
	pkt->pkt_len = mulen;
	rte_eth_tx_burst(1, ctrl_port_q, &pkt, 1);
}

static int lsi_event_callback(uint16_t port_id, enum rte_eth_event_type type, void *param)
{
	struct rte_eth_link link;
	tPPP_MBX			*mail = (tPPP_MBX *)rte_malloc(NULL,sizeof(tPPP_MBX),2048);

	RTE_SET_USED(param);

	printf("\n\nIn registered callback...\n");
	printf("Event type: %s\n", type == RTE_ETH_EVENT_INTR_LSC ? "LSC interrupt" : "unknown event");
	rte_eth_link_get_nowait(port_id, &link);
	if (link.link_status) {
		printf("Port %d Link Up - speed %u Mbps - %s\n\n",
				port_id, (unsigned)link.link_speed,
			(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
				("full-duplex") : ("half-duplex"));
		mail->refp[0] = LINK_UP;
		mail->type = IPC_EV_TYPE_REG;
		mail->len = 1;
		//enqueue up event to main thread
		rte_ring_enqueue_burst(rte_ring,(void **)&mail,1,NULL);
	} 
	else {
		printf("Port %d Link Down\n\n", port_id);
		mail->refp[0] = LINK_DOWN;
		mail->type = IPC_EV_TYPE_REG;
		mail->len = 1;
		//enqueue down event to main thread
		rte_ring_enqueue_burst(rte_ring,(void **)&mail,1,NULL);
	}

	return 0;
}
