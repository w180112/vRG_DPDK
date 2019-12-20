/*\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\
  PPP_CODEC.H

  Designed by THE on Jan 14, 2019
/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\*/

#ifndef _CODEC_H_
#define _CODEC_H_

#include "pppoeclient.h"
#include "pppd.h"
#include <ip_codec.h>
#include "fsm.h"
#include <rte_timer.h>

extern STATUS PPP_decode_frame(tPPP_MBX *mail, struct rte_ether_hdr *eth_hdr, vlan_header_t *vlan_header, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_header_t *ppp_lcp, ppp_options_t *ppp_options, uint16_t *event, struct rte_timer *tim, tPPP_PORT *port_ccb);
extern STATUS decode_ipcp(pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_header_t *ppp_lcp, ppp_options_t *ppp_options, uint16_t total_lcp_length, uint16_t *event, struct rte_timer *tim, tPPP_PORT *port_ccb);

extern void   DECODE_OBJID(U8 *vp, U8 vlen, U32 *oids, U8 *oids_len);

extern STATUS build_config_request(unsigned char *buffer, tPPP_PORT *port_ccb, uint16_t *mulen);
extern STATUS build_config_ack(unsigned char *buffer, tPPP_PORT *port_ccb, uint16_t *mulen);
extern STATUS build_config_nak_rej(unsigned char *buffer, tPPP_PORT *port_ccb, uint16_t *mulen);
extern STATUS build_terminate_ack(unsigned char *buffer, tPPP_PORT *port_ccb, uint16_t *mulen);
extern STATUS build_code_reject(unsigned char *buffer, tPPP_PORT *port_ccb, uint16_t *mulen);
extern STATUS build_terminate_request(unsigned char *buffer, tPPP_PORT *port_ccb, uint16_t *mulen);
extern STATUS build_echo_reply(unsigned char *buffer, tPPP_PORT *port_ccb, uint16_t *mulen);
extern STATUS build_auth_request_pap(unsigned char *buffer, tPPP_PORT *port_ccb, uint16_t *mulen);
extern STATUS build_auth_ack_pap(unsigned char *buffer, tPPP_PORT *port_ccb, uint16_t *mulen);

STATUS check_nak_reject(uint8_t flag, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_header_t *ppp_lcp, ppp_options_t *ppp_options, uint16_t total_lcp_length);
STATUS check_ipcp_nak_rej(uint8_t flag, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_header_t *ppp_lcp, ppp_options_t *ppp_options, uint16_t total_lcp_length);

STATUS build_padi(__attribute__((unused)) struct rte_timer *tim, tPPP_PORT *port_ccb);
STATUS build_padr(__attribute__((unused)) struct rte_timer *tim, tPPP_PORT *port_ccb);
STATUS build_padt(tPPP_PORT *port_ccb);

extern 	tPPP_PORT	ppp_ports[MAX_USER];
extern  U8			ppp_802_1_oui[];
extern  U8  		ppp_da_mac[];
extern  char		cts_port_id[];
extern  char		cts_port_desc[];

#endif
