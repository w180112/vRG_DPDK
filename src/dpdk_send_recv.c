#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_arp.h>
#include <rte_ip.h>
#include <rte_icmp.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <rte_memcpy.h>
#include "pppoeclient.h"

#define RX_RING_SIZE 128

#define TX_RING_SIZE 512

#define BURST_SIZE 32

extern tPPP_PORT				ppp_ports[MAX_USER];
extern struct rte_mempool 		*mbuf_pool;
extern struct rte_ring 			*rte_ring;
extern struct rte_ring 			*decap;

static uint16_t 				nb_rxd = RX_RING_SIZE;
static uint16_t 				nb_txd = TX_RING_SIZE;

static const struct rte_eth_conf port_conf_default = {
	.rxmode = { .max_rx_pkt_len = ETHER_MAX_LEN, }, 
	.txmode = { .offloads = DEV_TX_OFFLOAD_IPV4_CKSUM | 
							DEV_TX_OFFLOAD_UDP_CKSUM | 
							DEV_TX_OFFLOAD_TCP_CKSUM, }
};
extern void 		nat_icmp_learning(struct ether_hdr *eth_hdr, struct ipv4_hdr *ip_hdr, struct icmp_hdr *icmphdr, uint32_t *new_port_id);
extern void 		nat_udp_learning(struct ether_hdr *eth_hdr, struct ipv4_hdr *ip_hdr, struct udp_hdr *udphdr, uint32_t *new_port_id);
extern void 		nat_tcp_learning(struct ether_hdr *eth_hdr, struct ipv4_hdr *ip_hdr, struct tcp_hdr *tcphdr, uint32_t *new_port_id);
extern uint16_t 	get_checksum(const void *const addr, const size_t bytes);
int 				PPP_PORT_INIT(uint16_t port);
int 				ppp_recvd(void);
void 				encapsulation_udp(struct rte_mbuf *single_pkt, struct ether_hdr *eth_hdr, struct ipv4_hdr *ip_hdr);
void 				encapsulation_tcp(struct rte_mbuf *single_pkt, struct ether_hdr *eth_hdr, struct ipv4_hdr *ip_hdr);
int 				control_plane_dequeue(tPPP_MBX **mail);
int 				decapsulation(void);
int 				gateway(void);
void 				drv_xmit(U8 *mu, U16 mulen);

int PPP_PORT_INIT(uint16_t port)
{
	struct rte_eth_conf port_conf = port_conf_default;
	struct rte_eth_dev_info dev_info;
	const uint16_t rx_rings = 1, tx_rings = 2;
	int retval;
	uint16_t q;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;
	rte_eth_dev_info_get(port, &dev_info);
	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |= DEV_TX_OFFLOAD_MBUF_FAST_FREE;

	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;
	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd,&nb_txd);
	if (retval < 0)
		rte_exit(EXIT_FAILURE,"Cannot adjust number of descriptors: err=%d, ""port=%d\n", retval, port);

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for(q=0; q<rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port,q,nb_rxd,rte_eth_dev_socket_id(port),NULL,mbuf_pool);
		if (retval < 0)
			return retval;
	}

	/* Allocate and set up 2 TX queue per Ethernet port. */
	for(q=0; q<tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port,q,nb_txd,rte_eth_dev_socket_id(port), NULL);
		if (retval < 0)
			return retval;
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;
	//rte_eth_promiscuous_enable(port);
	return 0;
}

int ppp_recvd(void)
{
	struct rte_mbuf 	*single_pkt;
	uint64_t 			total_tx;
	struct ether_hdr 	*eth_hdr,tmp_eth_hdr;
	struct ipv4_hdr 	*ip_hdr;
	struct icmp_hdr		*icmphdr;
	struct rte_mbuf 	*pkt[BURST_SIZE];
	uint16_t 			ori_port_id, nb_rx;
	ppp_payload_t 		*ppp_payload;
	tPPP_MBX 			*mail = malloc(sizeof(tPPP_MBX));
	int 				i;
	
	for(;;) {
		nb_rx = rte_eth_rx_burst(1,0,pkt,BURST_SIZE);
		if (nb_rx == 0)
			continue;
		total_tx = 0;
		for(i=0; i<nb_rx; i++) {
			single_pkt = pkt[i];
			rte_prefetch0(rte_pktmbuf_mtod(single_pkt, void *));
			eth_hdr = rte_pktmbuf_mtod(single_pkt,struct ether_hdr*);
			if (eth_hdr->ether_type != rte_cpu_to_be_16(ETH_P_PPP_SES) && eth_hdr->ether_type != rte_cpu_to_be_16(ETH_P_PPP_DIS)) {
				rte_pktmbuf_free(single_pkt);
				continue;
			}
			ppp_payload = ((ppp_payload_t *)((char *)eth_hdr + sizeof(struct ether_hdr) + sizeof(pppoe_header_t)));
			if (unlikely(eth_hdr->ether_type == rte_cpu_to_be_16(ETH_P_PPP_DIS) || (eth_hdr->ether_type == rte_cpu_to_be_16(ETH_P_PPP_SES) && (ppp_payload->ppp_protocol == rte_cpu_to_be_16(LCP_PROTOCOL) || ppp_payload->ppp_protocol == rte_cpu_to_be_16(AUTH_PROTOCOL) || ppp_payload->ppp_protocol == rte_cpu_to_be_16(IPCP_PROTOCOL))))) {
				rte_memcpy(mail->refp,eth_hdr,single_pkt->data_len);
				mail->type = IPC_EV_TYPE_DRV;
				mail->len = single_pkt->data_len;
				//enqueue eth_hdr single_pkt->data_len
				rte_ring_enqueue_burst(rte_ring,(void **)&mail,1,NULL);
				rte_pktmbuf_free(single_pkt);
				continue;
			}
			eth_hdr->ether_type = rte_cpu_to_be_16(FRAME_TYPE_IP);
			rte_memcpy(&tmp_eth_hdr,eth_hdr,sizeof(struct ether_hdr));
			rte_memcpy((char *)eth_hdr+8,&tmp_eth_hdr,sizeof(struct ether_hdr));
			single_pkt->data_off += 8;
			single_pkt->pkt_len -= 8;
			single_pkt->data_len -= 8;
			eth_hdr = (struct ether_hdr *)((char *)eth_hdr + 8);
			ip_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct ether_hdr));
			
			switch(ip_hdr->next_proto_id) {
				case PROTO_TYPE_ICMP:
					single_pkt->l2_len = sizeof(struct ether_hdr);
					single_pkt->l3_len = sizeof(struct ipv4_hdr);
					ip_hdr->hdr_checksum = 0;

					icmphdr = (struct icmp_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));
					single_pkt->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM;
					ori_port_id = rte_cpu_to_be_16(icmphdr->icmp_ident);
					rte_memcpy(eth_hdr->s_addr.addr_bytes,ppp_ports[0].lan_mac,6);
					rte_memcpy(eth_hdr->d_addr.addr_bytes,ppp_ports[0].addr_table[ori_port_id].mac_addr,6);
					ip_hdr->dst_addr = ppp_ports[0].addr_table[ori_port_id].src_ip;
					icmphdr->icmp_ident = ppp_ports[0].addr_table[ori_port_id].port_id;
					ppp_ports[0].addr_table[ori_port_id].is_alive = 10;

					icmphdr->icmp_cksum = 0;
					icmphdr->icmp_cksum = get_checksum(icmphdr,single_pkt->data_len - sizeof(struct ipv4_hdr));
					puts("nat mapping at port 1");
					break;
				case PROTO_TYPE_UDP:
				case PROTO_TYPE_TCP:
					rte_ring_enqueue_burst(decap,(void **)&single_pkt,1,NULL);
					rte_pktmbuf_free(single_pkt);
					continue;
				default:
					rte_pktmbuf_free(single_pkt);
					continue;
			}
			pkt[total_tx++] = single_pkt;
		}
		if (likely(total_tx > 0)) {
			uint16_t nb_tx = rte_eth_tx_burst(0,1,pkt,total_tx);
			if (unlikely(nb_tx < total_tx)) {
				for(uint16_t buf=nb_tx; buf<total_tx; buf++)
					rte_pktmbuf_free(pkt[buf]);
			}
		}
	}
	return 0;
}

int decapsulation(void)
{
	uint64_t 			total_tx;
	struct ether_hdr 	*eth_hdr;
	struct ipv4_hdr 	*ip_hdr;
	struct udp_hdr 		*udphdr;
	struct tcp_hdr 		*tcphdr;
	uint16_t 			ori_port_id, burst_size, nb_tx;
	struct rte_mbuf 	*pkt[BURST_SIZE], *single_pkt;
	int 				i;
	
	for(i=0; i<BURST_SIZE; i++)
		pkt[i] = rte_pktmbuf_alloc(mbuf_pool);

	for(;;) {
		burst_size = rte_ring_dequeue_burst(decap,(void **)pkt,BURST_SIZE,NULL);
		if (unlikely(burst_size == 0))
			continue;
		total_tx = 0;
		for(i=0; i<burst_size; i++) {
			single_pkt = pkt[i];
			rte_prefetch0(rte_pktmbuf_mtod(single_pkt,void *));
			eth_hdr = rte_pktmbuf_mtod(single_pkt,struct ether_hdr*);

			/* for NAT mapping */
			ip_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(single_pkt,unsigned char *) + sizeof(struct ether_hdr));
			
			single_pkt->l2_len = sizeof(struct ether_hdr);
			single_pkt->l3_len = sizeof(struct ipv4_hdr);
			ip_hdr->hdr_checksum = 0;

			switch(ip_hdr->next_proto_id) {
				case PROTO_TYPE_UDP: 
					single_pkt->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_UDP_CKSUM;
					udphdr = (struct udp_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));
					ori_port_id = rte_cpu_to_be_16(udphdr->dst_port);
					rte_memcpy(eth_hdr->s_addr.addr_bytes,ppp_ports[0].lan_mac,6);
					rte_memcpy(eth_hdr->d_addr.addr_bytes,ppp_ports[0].addr_table[ori_port_id].mac_addr,6);
					ip_hdr->dst_addr = ppp_ports[0].addr_table[ori_port_id].src_ip;
					udphdr->dst_port = ppp_ports[0].addr_table[ori_port_id].port_id;
					ppp_ports[0].addr_table[ori_port_id].is_alive = 10;

					udphdr->dgram_cksum = 0;
					break;
				case PROTO_TYPE_TCP:
					single_pkt->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_TCP_CKSUM;
					tcphdr = (struct tcp_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));
					ori_port_id = rte_cpu_to_be_16(tcphdr->dst_port);
					rte_memcpy(eth_hdr->s_addr.addr_bytes,ppp_ports[0].lan_mac,6);
					rte_memcpy(eth_hdr->d_addr.addr_bytes,ppp_ports[0].addr_table[ori_port_id].mac_addr,6);
					ip_hdr->dst_addr = ppp_ports[0].addr_table[ori_port_id].src_ip;
					tcphdr->dst_port = ppp_ports[0].addr_table[ori_port_id].port_id;
					ppp_ports[0].addr_table[ori_port_id].is_alive = 10;
					tcphdr->cksum = 0;
					break;
				default:
					;
			}
			pkt[total_tx++] = single_pkt;
		}
		if (likely(total_tx > 0))
			nb_tx = rte_eth_tx_burst(0,0,pkt,total_tx);
	}
	return 0;
}

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

void encapsulation_udp(struct rte_mbuf *single_pkt, struct ether_hdr *eth_hdr, struct ipv4_hdr *ip_hdr)
{
	struct udp_hdr 		*udphdr;
	char 				*cur;
	uint32_t 			new_port_id;
	pppoe_header_t 		*pppoe_header;

	/* for nat */
	single_pkt->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_UDP_CKSUM;

	udphdr = (struct udp_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));
	nat_udp_learning(eth_hdr,ip_hdr,udphdr,&new_port_id);
	ip_hdr->src_addr = ppp_ports[0].ipv4;
	udphdr->src_port = rte_cpu_to_be_16(new_port_id);
	ppp_ports[0].addr_table[new_port_id].is_alive = 10;
	ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);
	udphdr->dgram_cksum = 0;
	udphdr->dgram_cksum = rte_ipv4_udptcp_cksum(ip_hdr,udphdr);

	/* for PPPoE */
	rte_memcpy(eth_hdr->s_addr.addr_bytes,ppp_ports[0].src_mac,6);
	rte_memcpy(eth_hdr->d_addr.addr_bytes,ppp_ports[0].dst_mac,6);

	eth_hdr->ether_type = rte_cpu_to_be_16(ETH_P_PPP_SES);
	cur = (char *)eth_hdr - 8;
	rte_memcpy(cur,eth_hdr,14);
	pppoe_header = (pppoe_header_t *)(cur+14);
	pppoe_header->ver_type = 0x11;
	pppoe_header->code = 0;
	pppoe_header->session_id = ppp_ports[0].session_id;
	pppoe_header->length = rte_cpu_to_be_16((single_pkt->pkt_len) - 14 + 2);
	*((uint16_t *)(cur+14+sizeof(pppoe_header_t))) = rte_cpu_to_be_16(IP_PROTOCOL);
	single_pkt->data_off -= 8;
	single_pkt->pkt_len += 8;
	single_pkt->data_len += 8;
}

void encapsulation_tcp(struct rte_mbuf *single_pkt, struct ether_hdr *eth_hdr, struct ipv4_hdr *ip_hdr)
{
	struct tcp_hdr 		*tcphdr;
	uint32_t 			new_port_id;
	pppoe_header_t 		*pppoe_header;
	char 				*cur;
	
	/* for nat */
	single_pkt->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_TCP_CKSUM;

	tcphdr = (struct tcp_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));
	nat_tcp_learning(eth_hdr,ip_hdr,tcphdr,&new_port_id);
	ip_hdr->src_addr = ppp_ports[0].ipv4;
	tcphdr->src_port = rte_cpu_to_be_16(new_port_id);
	ppp_ports[0].addr_table[new_port_id].is_alive = 10;
	ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);
	tcphdr->cksum = 0;
	tcphdr->cksum = rte_ipv4_udptcp_cksum(ip_hdr,tcphdr);

	/* for PPPoE */
	rte_memcpy(eth_hdr->s_addr.addr_bytes,ppp_ports[0].src_mac,6);
	rte_memcpy(eth_hdr->d_addr.addr_bytes,ppp_ports[0].dst_mac,6);

	eth_hdr->ether_type = rte_cpu_to_be_16(ETH_P_PPP_SES);
	cur = (char *)eth_hdr - 8;
	rte_memcpy(cur,eth_hdr,14);
	pppoe_header = (pppoe_header_t *)(cur+14);
	pppoe_header->ver_type = 0x11;
	pppoe_header->code = 0;
	pppoe_header->session_id = ppp_ports[0].session_id;
	pppoe_header->length = rte_cpu_to_be_16((single_pkt->pkt_len) - 14 + 2);
	*((uint16_t *)(cur+14+sizeof(pppoe_header_t))) = rte_cpu_to_be_16(IP_PROTOCOL);
	single_pkt->data_off -= 8;
	single_pkt->pkt_len += 8;
	single_pkt->data_len += 8;
}

int gateway(void)
{
	struct rte_mbuf 	*single_pkt;
	uint64_t 			total_tx;
	struct ether_hdr 	*eth_hdr;
	struct ipv4_hdr 	*ip_hdr;
	struct icmp_hdr 	*icmphdr;
	struct rte_mbuf 	*pkt[BURST_SIZE];
	unsigned char 		mac_addr[6];
	struct arp_hdr		*arphdr;
	char 				*cur;
	int 				i;
	pppoe_header_t 		*pppoe_header;
	uint16_t 			nb_tx, nb_rx;
	uint32_t			lan_ip = rte_cpu_to_be_32(0xc0a80001); //192.168.0.1

	rte_eth_macaddr_get(0,(struct ether_addr *)mac_addr);
	while(ppp_ports[0].data_plane_start == FALSE)
		usleep(1000);
	for(;;) {
		nb_rx = rte_eth_rx_burst(0,0,pkt,BURST_SIZE);
		if (nb_rx == 0)
			continue;
		total_tx = 0;
		for(i=0; i<nb_rx; i++) {
			single_pkt = pkt[i];
			rte_prefetch0(rte_pktmbuf_mtod(single_pkt,void *));
			eth_hdr = rte_pktmbuf_mtod(single_pkt,struct ether_hdr*);
			if (eth_hdr->ether_type == rte_cpu_to_be_16(FRAME_TYPE_ARP)) { 
				/* We only reply arp request to us */
				rte_memcpy(eth_hdr->d_addr.addr_bytes,eth_hdr->s_addr.addr_bytes,6);
				rte_memcpy(eth_hdr->s_addr.addr_bytes,mac_addr,6);
				arphdr = (struct arp_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct ether_hdr));
				if (arphdr->arp_op == rte_cpu_to_be_16(ARP_OP_REQUEST) && arphdr->arp_data.arp_tip == lan_ip) {
					rte_memcpy(arphdr->arp_data.arp_tha.addr_bytes,arphdr->arp_data.arp_sha.addr_bytes,6);
					rte_memcpy(arphdr->arp_data.arp_sha.addr_bytes,mac_addr,6);
					arphdr->arp_data.arp_tip = arphdr->arp_data.arp_sip;
					arphdr->arp_data.arp_sip = lan_ip;
					arphdr->arp_op = rte_cpu_to_be_16(ARP_OP_REPLY);
					rte_eth_tx_burst(0,0,&single_pkt,1);
					continue;
				}
				rte_pktmbuf_free(single_pkt);
				continue;
			}
			else if (eth_hdr->ether_type == rte_cpu_to_be_16(ETH_P_PPP_DIS) || (eth_hdr->ether_type == rte_cpu_to_be_16(ETH_P_PPP_SES))) {
				rte_pktmbuf_free(single_pkt);
				continue;
			}
			else if (eth_hdr->ether_type == rte_cpu_to_be_16(FRAME_TYPE_IP)) {
				ip_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct ether_hdr));
				single_pkt->l2_len = sizeof(struct ether_hdr);
				single_pkt->l3_len = sizeof(struct ipv4_hdr);
				ip_hdr->hdr_checksum = 0;
				
				if (ip_hdr->next_proto_id == PROTO_TYPE_ICMP) {
					single_pkt->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM;
					icmphdr = (struct icmp_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));
					if (ip_hdr->dst_addr != lan_ip) {
						uint32_t 			new_port_id;

						nat_icmp_learning(eth_hdr,ip_hdr,icmphdr,&new_port_id);
						ip_hdr->src_addr = ppp_ports[0].ipv4;
						icmphdr->icmp_ident = rte_cpu_to_be_16(new_port_id);
						ppp_ports[0].addr_table[new_port_id].is_alive = 10;
						ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);
						icmphdr->icmp_cksum = 0;
						icmphdr->icmp_cksum = get_checksum(icmphdr,single_pkt->data_len - sizeof(struct ipv4_hdr));

						rte_memcpy(eth_hdr->s_addr.addr_bytes,ppp_ports[0].src_mac,6);
						rte_memcpy(eth_hdr->d_addr.addr_bytes,ppp_ports[0].dst_mac,6);

						eth_hdr->ether_type = rte_cpu_to_be_16(ETH_P_PPP_SES);
						cur = (char *)eth_hdr - 8;
						rte_memcpy(cur,eth_hdr,14);
						pppoe_header = (pppoe_header_t *)(cur+14);
						pppoe_header->ver_type = 0x11;
						pppoe_header->code = 0;
						pppoe_header->session_id = ppp_ports[0].session_id;
						pppoe_header->length = rte_cpu_to_be_16((single_pkt->pkt_len) - 14 + 2);
						*((uint16_t *)(cur+14+sizeof(pppoe_header_t))) = rte_cpu_to_be_16(IP_PROTOCOL);//protocol;
						single_pkt->data_off -= 8;
						single_pkt->pkt_len += 8;
						single_pkt->data_len += 8;
						
						pkt[total_tx++] = single_pkt;
						puts("nat icmp at port 0");
					}
					else {
						memcpy(eth_hdr->d_addr.addr_bytes,eth_hdr->s_addr.addr_bytes,6);
						memcpy(eth_hdr->s_addr.addr_bytes,mac_addr,6);
						ip_hdr->dst_addr = ip_hdr->src_addr;
						ip_hdr->src_addr = lan_ip;
						icmphdr->icmp_type = 0;
						uint32_t cksum = ~icmphdr->icmp_cksum & 0xffff;
						cksum += ~rte_cpu_to_be_16(8 << 8) & 0xffff;
						cksum += rte_cpu_to_be_16(0 << 8);
		  				cksum = (cksum & 0xffff) + (cksum >> 16);
						cksum = (cksum & 0xffff) + (cksum >> 16);
						icmphdr->icmp_cksum = ~cksum;
						rte_eth_tx_burst(0,0,&single_pkt,1);
						continue;
					}
				}
				else if (ip_hdr->next_proto_id == PROTO_TYPE_TCP) {
					encapsulation_tcp(single_pkt,eth_hdr,ip_hdr);
					pkt[total_tx++] = single_pkt;
				}
				else if (ip_hdr->next_proto_id == PROTO_TYPE_UDP) {
					encapsulation_udp(single_pkt,eth_hdr,ip_hdr);
					pkt[total_tx++] = single_pkt;
				}
				else {
					puts("unknown L4 packet recv on gateway LAN port queue");
					rte_pktmbuf_free(single_pkt);
				}
			}
			else {
				puts("unknown ether type recv on gateway LAN port queue");
				rte_pktmbuf_free(single_pkt);
				continue;
			}
		}
		if (likely(total_tx > 0)) {
			nb_tx = rte_eth_tx_burst(1,0,pkt,total_tx);
			if (unlikely(nb_tx < total_tx)) {
				for(uint16_t buf=nb_tx; buf<total_tx; buf++)
					rte_pktmbuf_free(pkt[buf]);
			}
		}
	}
	return 0;
}

void drv_xmit(U8 *mu, U16 mulen)
{
	struct rte_mbuf *pkt;
	char 			*buf;

	pkt = rte_pktmbuf_alloc(mbuf_pool);
	buf = rte_pktmbuf_mtod(pkt,char *);
	rte_memcpy(buf,mu,mulen);
	pkt->data_len = mulen;
	pkt->pkt_len = mulen;
	rte_eth_tx_burst(1,1,&pkt,1);
}
