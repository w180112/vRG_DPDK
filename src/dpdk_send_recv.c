#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include "pppoeclient.h"

#define RX_RING_SIZE 128

#define TX_RING_SIZE 512

#define BURST_SIZE 32

extern unsigned char 			*src_mac;
extern unsigned char 			*dst_mac;
extern uint16_t		 			session_id;
extern struct rte_mempool 		*mbuf_pool;
extern struct rte_ring 			*rte_ring;

static const struct rte_eth_conf port_conf_default = {
	.rxmode = { .max_rx_pkt_len = ETHER_MAX_LEN }
};

int PPP_PORT_INIT(uint16_t port)
{
	struct rte_eth_conf port_conf = port_conf_default;
	struct rte_eth_dev_info dev_info;
	const uint16_t rx_rings = 1, tx_rings = 1;
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

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for(q=0; q<rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port,q,RX_RING_SIZE,rte_eth_dev_socket_id(port),NULL,mbuf_pool);
		if (retval < 0)
			return retval;
	}

	/* Allocate and set up 1 TX queue per Ethernet port. */
	for(q=0; q<tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port,q,TX_RING_SIZE,rte_eth_dev_socket_id(port), NULL);
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
	struct ether_hdr 	*eth_hdr;
	pppoe_header_t 		*pppoe_header;
	for(;;) {
		struct rte_mbuf *pkt[BURST_SIZE];

		uint16_t nb_rx = rte_eth_rx_burst(1,0,pkt,BURST_SIZE);
		if(nb_rx == 0)
			continue;
		total_tx = 0;
		for(int i=0; i<nb_rx; i++) {
			single_pkt = pkt[i];
			eth_hdr = rte_pktmbuf_mtod(single_pkt,struct ether_hdr*);
			if (eth_hdr->ether_type != htons(0x8864) && eth_hdr->ether_type != htons(0x8863)) {
				rte_pktmbuf_free(single_pkt);
				continue;
			}
			ppp_payload_t *ppp_payload = ((ppp_payload_t *)((char *)eth_hdr + sizeof(struct ether_hdr) + sizeof(pppoe_header_t)));
			if (unlikely(eth_hdr->ether_type == htons(0x8863) || (eth_hdr->ether_type == htons(0x8864) && (ppp_payload->ppp_protocol == htons(LCP_PROTOCOL) || ppp_payload->ppp_protocol == htons(AUTH_PROTOCOL) || ppp_payload->ppp_protocol == htons(IPCP_PROTOCOL))))) {
				tPPP_MBX *mail = malloc(sizeof(tPPP_MBX));

				memcpy(mail->refp,eth_hdr,single_pkt->data_len);
				mail->type = IPC_EV_TYPE_DRV;
				mail->len = single_pkt->data_len;
				//enqueue eth_hdr single_pkt->data_len
				uint8_t ret = rte_ring_enqueue_burst(rte_ring,&mail,1,NULL);
				rte_pktmbuf_free(single_pkt);
				free(mail);
				continue;
			}
			memcpy(eth_hdr->s_addr.addr_bytes,dst_mac,6);
			memcpy(eth_hdr->d_addr.addr_bytes,src_mac,6);
			eth_hdr->ether_type = ppp_payload->ppp_protocol;
			memcpy((char *)eth_hdr+8,eth_hdr,sizeof(struct ether_hdr));
			single_pkt->data_off += 8;
			single_pkt->pkt_len -= 8;
			single_pkt->data_len -= 8;
			pkt[total_tx++] = single_pkt;
		}
		if (total_tx > 0) {
			uint16_t nb_tx = rte_eth_tx_burst(0,0,pkt,total_tx);
			if (unlikely(nb_tx < total_tx)) {
				for(uint16_t buf=nb_tx; buf<total_tx; buf++)
					rte_pktmbuf_free(pkt[buf]);
			}
		}
	}
	return 0;

}

tPPP_MBX *control_plane_dequeue(tPPP_MBX *mail)
{
	for(;;) {
		uint16_t burst_size = rte_ring_dequeue_burst(rte_ring,&mail,1,NULL);
		if (likely(burst_size == 0)) {
			continue;
		}
		printf("recv %u ring msg\n", burst_size);
		break;
	}
	return mail;
}

int encapsulation(void)
{
	struct rte_mbuf 	*single_pkt;
	uint64_t 			total_tx;
	struct ether_hdr 	*eth_hdr;
	pppoe_header_t 		*pppoe_header;

	while(data_plane_start == FALSE);
	for(;;) {
		struct rte_mbuf *pkt[BURST_SIZE];

		uint16_t nb_rx = rte_eth_rx_burst(0,0,pkt,BURST_SIZE);
		if (nb_rx == 0)
			continue;
		total_tx = 0;
		for(int i=0; i<nb_rx; i++) {
			single_pkt = pkt[i];
			eth_hdr = rte_pktmbuf_mtod(single_pkt,struct ether_hdr*);

			memcpy(eth_hdr->s_addr.addr_bytes,src_mac,6);
			memcpy(eth_hdr->d_addr.addr_bytes,dst_mac,6);

			uint16_t protocol = eth_hdr->ether_type;
			eth_hdr->ether_type = htons(0x8864);
			char *cur = (char *)eth_hdr - 8;
			memcpy(cur,eth_hdr,14);
			pppoe_header = (pppoe_header_t *)(cur+14);
			pppoe_header->ver_type = 0x11;
			pppoe_header->code = 0;
			pppoe_header->session_id = session_id;
			pppoe_header->length = htons((single_pkt->pkt_len) - 14 + 2);
			*((uint16_t *)(cur+14+sizeof(pppoe_header_t))) = protocol;
			single_pkt->data_off -= 8;
			single_pkt->pkt_len += 8;
			single_pkt->data_len += 8;
			pkt[total_tx++] = single_pkt;
		}
		if (total_tx > 0) {
			uint16_t nb_tx = rte_eth_tx_burst(1,0,pkt,total_tx);
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
	memcpy(buf,mu,mulen);
	pkt->data_len = mulen;
	pkt->pkt_len = mulen;
	
	uint16_t nb_tx = rte_eth_tx_burst(1,0,&pkt,1);
	rte_pktmbuf_free(pkt);
}
