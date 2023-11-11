/*\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\
  PPP_CODEC.H

  Designed by THE on Jan 14, 2019
/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\*/

#ifndef _CODEC_H_
#define _CODEC_H_

#include <common.h>
#include <rte_timer.h>
#include <ip_codec.h>
#include "../vrg.h"
#include "header.h"
#include "pppd.h"
#include "fsm.h"

void codec_init(VRG_t *ccb);

extern STATUS PPP_decode_frame(tVRG_MBX *mail, struct rte_ether_hdr *eth_hdr, vlan_header_t *vlan_header, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_header_t *ppp_hdr, ppp_options_t *ppp_options, U16 *event, PPP_INFO_t *s_ppp_ccb);
extern STATUS decode_ipcp(pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_header_t *ppp_hdr, ppp_options_t *ppp_options, U16 total_lcp_length, U16 *event, struct rte_timer *tim, PPP_INFO_t *s_ppp_ccb);

void build_config_request(U8 *buffer, U16 *mulen, PPP_INFO_t *s_ppp_ccb);
void build_config_ack(U8 *buffer, U16 *mulen, PPP_INFO_t *s_ppp_ccb);
void build_config_nak_rej(U8 *buffer, U16 *mulen, PPP_INFO_t *s_ppp_ccb);
void build_terminate_ack(U8 *buffer, U16 *mulen, PPP_INFO_t *s_ppp_ccb);
extern STATUS build_code_reject(U8 *buffer, PPP_INFO_t *s_ppp_ccb, U16 *mulen);
void build_terminate_request(U8 *buffer, U16 *mulen, PPP_INFO_t *s_ppp_ccb);
void build_echo_reply(U8 *buffer, U16 *mulen, PPP_INFO_t *s_ppp_ccb);
void build_auth_request_pap(U8 *buffer, U16 *mulen, PPP_INFO_t *s_ppp_ccb);
void build_auth_ack_pap(U8 *buffer, U16 *mulen, PPP_INFO_t *s_ppp_ccb);
STATUS build_auth_response_chap(U8 *buffer, PPP_INFO_t *s_ppp_ccb, U16 *mulen, ppp_chap_data_t *ppp_chap_data);

STATUS check_nak_reject(U8 flag, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_header_t *ppp_hdr, ppp_options_t *ppp_options, U16 total_lcp_length);
STATUS check_ipcp_nak_rej(U8 flag, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_header_t *ppp_hdr, ppp_options_t *ppp_options, U16 total_lcp_length);

STATUS build_padi(U8 *buffer, U16 *mulen, PPP_INFO_t *s_ppp_ccb);
STATUS build_padr(U8 *buffer, U16 *mulen, PPP_INFO_t *s_ppp_ccb);
void build_padt(U8 *buffer, U16 *mulen, PPP_INFO_t *s_ppp_ccb);
STATUS send_pkt(U8 encode_type, PPP_INFO_t *s_ppp_ccb);

typedef enum {
	ENCODE_PADI,
	ENCODE_PADR,
	ENCODE_PADT,
}PPP_CODE_TYPE_t;

#endif
