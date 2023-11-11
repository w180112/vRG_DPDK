#include <rte_timer.h>
#include <rte_ether.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_byteorder.h>
#include <cmdline_socket.h>
#include "../protocol.h"
#include "../dbg.h"
#include "../vrg.h"
#include "../dp.h"
#include "codec.h"

extern STATUS PPP_FSM(struct rte_timer *ppp, PPP_INFO_t *s_ppp_ccb, U16 event);

extern struct rte_ring 		*rte_ring, *gateway_q, *uplink_q, *downlink_q;
extern struct rte_ether_addr wan_mac;
extern struct cmdline 		*cl;
extern struct lcore_map 	lcore;
extern FILE					*fp;
extern BOOL					quit_flag;

U16 auth_method;
static VRG_t *vrg_ccb;

/*============================ DECODE ===============================*/

/**
 * @brief ppp_decode_frame() is for decode pppoe and ppp pkts
 * 
 * @param mail 
 * @param eth_hdr 
 * @param vlan_header 
 * @param pppoe_header 
 * @param ppp_payload 
 * @param ppp_hdr 
 * @param ppp_options 
 * @param event 
 * @param s_ppp_ccb 
 * @retval TRUE for decode successfully
 * @retval FALSE for decode failed 
 */
STATUS PPP_decode_frame(tVRG_MBX *mail, struct rte_ether_hdr *eth_hdr, vlan_header_t *vlan_header, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_header_t *ppp_hdr, ppp_options_t *ppp_options, U16 *event, PPP_INFO_t *s_ppp_ccb)
{
    U16	mulen;
	struct rte_timer *tim = &s_ppp_ccb->ppp;

	if (mail->len > ETH_MTU) {
	    VRG_LOG(ERR, vrg_ccb->fp, s_ppp_ccb, PPPLOGMSG, "error! too large frame(%d)", mail->len);
		/* TODO: store pkt buffer to log file, not just print out */
		PRINT_MESSAGE(mail->refp, mail->len);
	    return ERROR;
	}

	struct rte_ether_hdr *tmp_eth_hdr = (struct rte_ether_hdr *)mail->refp;
	vlan_header_t *tmp_vlan_header = (vlan_header_t *)(tmp_eth_hdr + 1);
	pppoe_header_t *tmp_pppoe_header = (pppoe_header_t *)(tmp_vlan_header + 1);
	rte_memcpy(eth_hdr,tmp_eth_hdr,sizeof(struct rte_ether_hdr));
	rte_memcpy(vlan_header,tmp_vlan_header,sizeof(vlan_header_t));
	rte_memcpy(pppoe_header,tmp_pppoe_header,sizeof(pppoe_header_t));

	/* we receive pppoe discovery packet and dont need to parse for ppp payload */
	if (vlan_header->next_proto == rte_cpu_to_be_16(ETH_P_PPP_DIS)) {
		if (pppoe_header->code == PADS)
			s_ppp_ccb->phase = LCP_PHASE;
		return FALSE;
	}
	
	ppp_payload_t *tmp_ppp_payload = (ppp_payload_t *)(tmp_pppoe_header + 1);
	ppp_header_t *tmp_ppp_hdr = (ppp_header_t *)(tmp_ppp_payload + 1);

	rte_memcpy(ppp_payload,tmp_ppp_payload,sizeof(ppp_payload_t));
	rte_memcpy(ppp_hdr,tmp_ppp_hdr,sizeof(ppp_header_t));
	U16 total_lcp_length = rte_be_to_cpu_16(ppp_hdr->length);
	rte_memcpy(ppp_options,tmp_ppp_hdr+1,total_lcp_length-sizeof(ppp_header_t));

	mulen = mail->len;

    mulen -= 14; //DA-MAC[6] + SA-MAC[6] + ETH-TYPE[2]

    /* check the ppp is in LCP, AUTH or NCP phase */
    if (ppp_payload->ppp_protocol == rte_cpu_to_be_16(IPCP_PROTOCOL)) {
    	if (s_ppp_ccb->phase != IPCP_PHASE)
    		return ERROR;
    	if (decode_ipcp(pppoe_header,ppp_payload,ppp_hdr,ppp_options,total_lcp_length,event,tim,s_ppp_ccb) == FALSE){
    		return ERROR;
    	}
    }
    else if (ppp_payload->ppp_protocol == rte_cpu_to_be_16(LCP_PROTOCOL)) {
		switch(ppp_hdr->code) {
			case CONFIG_REQUEST : 
				if (s_ppp_ccb->phase != LCP_PHASE)
    				return ERROR;
				auth_method = s_ppp_ccb->auth_method;
				/* we check for if the request packet contains what we want */
				switch (check_nak_reject(CONFIG_NAK,pppoe_header,ppp_payload,ppp_hdr,ppp_options,total_lcp_length)) {
					case ERROR:
						return ERROR;
					case 1:
						*event = E_RECV_BAD_CONFIG_REQUEST;
						return TRUE;
					default:
						;
				}
				switch (check_nak_reject(CONFIG_REJECT,pppoe_header,ppp_payload,ppp_hdr,ppp_options,total_lcp_length)) {
					case ERROR:
						return ERROR;
					case 1:
						*event = E_RECV_BAD_CONFIG_REQUEST;
						return TRUE;
					default:
						;
				}
				s_ppp_ccb->auth_method = auth_method;
				*event = E_RECV_GOOD_CONFIG_REQUEST;
				ppp_hdr->length = rte_cpu_to_be_16(total_lcp_length);
				return TRUE;
			case CONFIG_ACK :
				if (s_ppp_ccb->phase != LCP_PHASE)
    				return ERROR;
				if (ppp_hdr->identifier != s_ppp_ccb->identifier)
					return ERROR;
			
				/* only check magic number. Skip the bytes stored in ppp_options_t length to find magic num. */
				U8 ppp_options_length = 0;
				for(ppp_options_t *cur=ppp_options; ppp_options_length<(rte_cpu_to_be_16(ppp_hdr->length)-4);) {
					if (cur->type == MAGIC_NUM) {
						for(int i=cur->length-3; i>=0; i--) {
							if (*(((U8 *)&(s_ppp_ccb->magic_num)) + i) != cur->val[i]) {
								VRG_LOG(ERR, vrg_ccb->fp, s_ppp_ccb, PPPLOGMSG, "Session 0x%x recv ppp LCP magic number error.", rte_cpu_to_be_16(s_ppp_ccb->session_id));
								return ERROR;
							}
						}
					}
					ppp_options_length += cur->length;
					cur = (ppp_options_t *)((char *)cur + cur->length);
				}
				*event = E_RECV_CONFIG_ACK;
				rte_timer_stop(tim);
				return TRUE;
			case CONFIG_NAK : 
				*event = E_RECV_CONFIG_NAK_REJ;
				if (ppp_options->type == AUTH)
					s_ppp_ccb->auth_method = PAP_PROTOCOL;
				VRG_LOG(WARN, vrg_ccb->fp, s_ppp_ccb, PPPLOGMSG, "User %" PRIu16 " recv LCP nak message with option %x.", s_ppp_ccb->user_num, ppp_options->type);
				return TRUE;
			case CONFIG_REJECT :
				*event = E_RECV_CONFIG_NAK_REJ;
				VRG_LOG(WARN, vrg_ccb->fp, s_ppp_ccb, PPPLOGMSG, "User %" PRIu16 " recv LCP reject message with option %x.", s_ppp_ccb->user_num, ppp_options->type);
				if (ppp_options->type == AUTH) {
					if (s_ppp_ccb->is_pap_auth == TRUE)
						return ERROR;
					s_ppp_ccb->is_pap_auth = TRUE;
					s_ppp_ccb->auth_method = PAP_PROTOCOL;
				}
				return TRUE;
			case TERMIN_REQUEST :
				*event = E_RECV_TERMINATE_REQUEST;
				return TRUE;
			case TERMIN_ACK :
				*event = E_RECV_TERMINATE_ACK;
				rte_timer_stop(tim);
				return TRUE;
			case CODE_REJECT:
				*event = E_RECV_GOOD_CODE_PROTOCOL_REJECT;
				return TRUE;
			case PROTO_REJECT:
				*event = E_RECV_BAD_CODE_PROTOCOL_REJECT;
				return TRUE;
			case ECHO_REQUEST:
				if (s_ppp_ccb->phase < LCP_PHASE)
    				return ERROR;
				rte_timer_stop(&(s_ppp_ccb->ppp_alive));
				rte_timer_reset(&(s_ppp_ccb->ppp_alive), ppp_interval*rte_get_timer_hz(), SINGLE, lcore.timer_thread, (rte_timer_cb_t)exit_ppp, s_ppp_ccb);
				*event = E_RECV_ECHO_REPLY_REQUEST_DISCARD_REQUEST;
				return TRUE;
			case ECHO_REPLY:
				if (s_ppp_ccb->phase < LCP_PHASE)
    				return ERROR;
				*event = E_RECV_ECHO_REPLY_REQUEST_DISCARD_REQUEST;
				return TRUE;
			default :
				*event = E_RECV_UNKNOWN_CODE;
		}
	}

	/* in AUTH phase, if the packet is not what we want, then send nak packet and just close process */
	else if (ppp_payload->ppp_protocol == rte_cpu_to_be_16(PAP_PROTOCOL)) {
		if (s_ppp_ccb->phase != AUTH_PHASE)
			return ERROR;
		//ppp_pap_ack_nak_t ppp_pap_ack_nak, *tmp_ppp_pap_ack_nak = (ppp_pap_ack_nak_t *)(tmp_ppp_hdr + 1);
		//rte_memcpy(&ppp_pap_ack_nak,tmp_ppp_pap_ack_nak,tmp_ppp_pap_ack_nak->msg_length + sizeof(U8));
		if (ppp_hdr->code == PAP_ACK) {
			VRG_LOG(INFO, vrg_ccb->fp, s_ppp_ccb, PPPLOGMSG, "User %" PRIu16 " auth success.", s_ppp_ccb->user_num);
			s_ppp_ccb->phase = IPCP_PHASE;
			return TRUE;
		}
		else if (ppp_hdr->code == PAP_NAK) {
    		s_ppp_ccb->phase = LCP_PHASE;
    		PPP_FSM(&(s_ppp_ccb->ppp),s_ppp_ccb,E_CLOSE);
			VRG_LOG(WARN, vrg_ccb->fp, s_ppp_ccb, PPPLOGMSG, "User %" PRIu16 " auth fail.", s_ppp_ccb->user_num);
			return TRUE;
		}
		else if (ppp_hdr->code == PAP_REQUEST) {
			U8 buffer[MSG_BUF];
    		U16 mulen;
    		PPP_INFO_t tmp_s_ppp_ccb;

    		s_ppp_ccb->phase = AUTH_PHASE;
    		tmp_s_ppp_ccb.ppp_phase[0].eth_hdr = eth_hdr;
			tmp_s_ppp_ccb.ppp_phase[0].vlan_header = vlan_header;
    		tmp_s_ppp_ccb.ppp_phase[0].pppoe_header = pppoe_header;
    		tmp_s_ppp_ccb.ppp_phase[0].ppp_payload = ppp_payload;
    		tmp_s_ppp_ccb.ppp_phase[0].ppp_hdr = ppp_hdr;
    		tmp_s_ppp_ccb.ppp_phase[0].ppp_options = NULL;
    		tmp_s_ppp_ccb.cp = 0;
			tmp_s_ppp_ccb.session_id = s_ppp_ccb->session_id;

			build_auth_ack_pap(buffer, &mulen, &tmp_s_ppp_ccb);
			drv_xmit(vrg_ccb, buffer, mulen);
			VRG_LOG(INFO, vrg_ccb->fp, s_ppp_ccb, PPPLOGMSG, "User %" PRIu16 " recv pap request.\n", s_ppp_ccb->user_num);
			return TRUE;
		}
	}
	else if (ppp_payload->ppp_protocol == rte_cpu_to_be_16(CHAP_PROTOCOL)) {
		if (s_ppp_ccb->phase != AUTH_PHASE)
			return ERROR;
		ppp_chap_data_t *ppp_chap_data = (ppp_chap_data_t *)(tmp_ppp_hdr + 1);
		if (ppp_hdr->code == CHAP_CHALLANGE) {
			U8 buffer[MSG_BUF];
    		U16 mulen;
    		PPP_INFO_t tmp_s_ppp_ccb;

    		s_ppp_ccb->phase = AUTH_PHASE;
    		tmp_s_ppp_ccb.ppp_phase[0].eth_hdr = eth_hdr;
			tmp_s_ppp_ccb.ppp_phase[0].vlan_header = vlan_header;
    		tmp_s_ppp_ccb.ppp_phase[0].pppoe_header = pppoe_header;
    		tmp_s_ppp_ccb.ppp_phase[0].ppp_payload = ppp_payload;
    		tmp_s_ppp_ccb.ppp_phase[0].ppp_hdr = ppp_hdr;
    		tmp_s_ppp_ccb.ppp_phase[0].ppp_options = NULL;
    		tmp_s_ppp_ccb.cp = 0;
			tmp_s_ppp_ccb.session_id = s_ppp_ccb->session_id;
			if (build_auth_response_chap(buffer, &tmp_s_ppp_ccb, &mulen, ppp_chap_data) < 0)
				return ERROR;
				
			drv_xmit(vrg_ccb, buffer, mulen);
			VRG_LOG(INFO, vrg_ccb->fp, s_ppp_ccb, PPPLOGMSG, "User %" PRIu16 " recv chap challenge.", s_ppp_ccb->user_num);
			return TRUE;
		}
		else if (ppp_hdr->code == CHAP_SUCCESS) {
			VRG_LOG(INFO, vrg_ccb->fp, s_ppp_ccb, PPPLOGMSG, "User %" PRIu16 " auth success.", s_ppp_ccb->user_num);
			s_ppp_ccb->phase = IPCP_PHASE;
			return TRUE;
		}
		else if (ppp_hdr->code == CHAP_FAILURE) {
    		s_ppp_ccb->phase = LCP_PHASE;
			VRG_LOG(ERR, vrg_ccb->fp, s_ppp_ccb, PPPLOGMSG, "User %" PRIu16 " auth fail.", s_ppp_ccb->user_num);
			return TRUE;
		}
	}
	else {
		VRG_LOG(WARN, vrg_ccb->fp, s_ppp_ccb, PPPLOGMSG, "User %" PRIu16 " recv unknown PPP protocol.", s_ppp_ccb->user_num);
		return ERROR;
	}

	return TRUE;
}

/*******************************************************************
 * decode_ipcp
 * 
 * input : pppoe_header,ppp_payload,ppp_hdr,
 * 			ppp_options,total_lcp_length,event,tim,s_ppp_ccb
 * output: event
 * return: error
 *******************************************************************/
STATUS decode_ipcp(pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_header_t *ppp_hdr, ppp_options_t *ppp_options, U16 total_lcp_length, U16 *event, struct rte_timer *tim, PPP_INFO_t *s_ppp_ccb)
{
	switch(ppp_hdr->code) {
		case CONFIG_REQUEST : 
			switch (check_ipcp_nak_rej(CONFIG_NAK,pppoe_header,ppp_payload,ppp_hdr,ppp_options,total_lcp_length)) {
				case ERROR:
					return FALSE;
				case 1:
					*event = E_RECV_BAD_CONFIG_REQUEST;
					return TRUE;
				default:
					;
			}
			switch (check_ipcp_nak_rej(CONFIG_REJECT,pppoe_header,ppp_payload,ppp_hdr,ppp_options,total_lcp_length)) {
				case ERROR:
					return FALSE;
				case 1:
					*event = E_RECV_BAD_CONFIG_REQUEST;
					return TRUE;
				default:
					;
			}
			rte_memcpy(&(s_ppp_ccb->hsi_ipv4_gw),ppp_options->val,sizeof(s_ppp_ccb->hsi_ipv4_gw));
			*event = E_RECV_GOOD_CONFIG_REQUEST;
			ppp_hdr->length = rte_cpu_to_be_16(total_lcp_length);
			return TRUE;
		case CONFIG_ACK :
			if (ppp_hdr->identifier != s_ppp_ccb->identifier)
				return FALSE;
			rte_timer_stop(tim);
			*event = E_RECV_CONFIG_ACK;
			rte_memcpy(&(s_ppp_ccb->hsi_ipv4),ppp_options->val,sizeof(s_ppp_ccb->hsi_ipv4));
			return TRUE;
		case CONFIG_NAK : 
			// if we receive nak packet, the option field contains correct ip address we want
			rte_memcpy(&(s_ppp_ccb->hsi_ipv4),ppp_options->val,4);
			*event = E_RECV_CONFIG_NAK_REJ;
			return TRUE;
		case CONFIG_REJECT :
			*event = E_RECV_CONFIG_NAK_REJ;
			return TRUE;
		case TERMIN_REQUEST :
			*event = E_RECV_TERMINATE_REQUEST;
			return TRUE;
		case TERMIN_ACK :
			VRG_LOG(INFO, vrg_ccb->fp, s_ppp_ccb, PPPLOGMSG, "User %" PRIu16 " vlan 0x%x recv termin ack.", s_ppp_ccb->user_num, s_ppp_ccb->vlan);
			rte_timer_stop(tim);
			*event = E_RECV_TERMINATE_ACK;
			return TRUE;
		case CODE_REJECT:
			*event = E_RECV_GOOD_CODE_PROTOCOL_REJECT;
			return TRUE;
		default :
			*event = E_RECV_UNKNOWN_CODE;
	}
	return TRUE;
}

/**
 * check_ipcp_nak_rej
 *
 * purpose: check whether IPCP config request we received includes PPP options we dont want.
 * input: 	flag - check NAK/REJ,
 * 		    *pppoe_header, 
 * 		    *ppp_payload, 
 * 		    *ppp_hdr, 
 * 		    *ppp_options, 
 * 		    total_lcp_length
 * output: 	TRUE/FALSE
 * return: 	should send NAK/REJ or ACK
 **/
STATUS check_ipcp_nak_rej(U8 flag, pppoe_header_t *pppoe_header, __attribute__((unused)) ppp_payload_t *ppp_payload, ppp_header_t *ppp_hdr, ppp_options_t *ppp_options, U16 total_lcp_length)
{
	ppp_options_t *tmp_buf = (ppp_options_t *)rte_malloc(NULL,MSG_BUF*sizeof(char),0);
	ppp_options_t *tmp_cur = tmp_buf;
	int bool_flag = 0;
	U16 tmp_total_length = 4;
	
	memset(tmp_buf,0,MSG_BUF);
	rte_memcpy(tmp_buf, ppp_options, total_lcp_length-sizeof(ppp_header_t));

	ppp_hdr->length = sizeof(ppp_header_t);
	for (ppp_options_t *cur=ppp_options; tmp_total_length<total_lcp_length; cur=(ppp_options_t *)((char *)cur + cur->length)) {
		if (flag == CONFIG_NAK) {
			if (cur->type == IP_ADDRESS && cur->val[0] == 0) {
				bool_flag = 1;
				rte_memcpy(tmp_cur,cur,cur->length);
				ppp_hdr->length += cur->length;
				tmp_cur = (ppp_options_t *)((char *)tmp_cur + cur->length);
			}
		}
		else {
			if (cur->type != IP_ADDRESS) {
				bool_flag = 1;
				rte_memcpy(tmp_cur,cur,cur->length);
				ppp_hdr->length += cur->length;
				tmp_cur = (ppp_options_t *)((char *)tmp_cur + cur->length);
			}
		}
		tmp_total_length += cur->length;
	}

	if (bool_flag == 1) {
		rte_memcpy(ppp_options,tmp_buf,ppp_hdr->length - sizeof(ppp_header_t));
		pppoe_header->length = rte_cpu_to_be_16((ppp_hdr->length) + sizeof(ppp_payload_t));
		ppp_hdr->length = rte_cpu_to_be_16(ppp_hdr->length);
		ppp_hdr->code = flag;
		rte_free(tmp_buf);

		return 1;
	}
	rte_free(tmp_buf);
	return 0;
}

/**
 * check_lcp_nak_rej
 *
 * purpose: check whether LCP config request we received includes PPP options we dont want.
 * input: 	flag - check NAK/REJ,
 * 		    *pppoe_header, 
 * 		    *ppp_payload, 
 * 		    *ppp_hdr, 
 * 		    *ppp_options, 
 * 		    total_lcp_length
 * output: 	TRUE/FALSE
 * return: 	should send NAK/REJ or ACK
 **/
STATUS check_nak_reject(U8 flag, pppoe_header_t *pppoe_header, __attribute__((unused)) ppp_payload_t *ppp_payload, ppp_header_t *ppp_hdr, ppp_options_t *ppp_options, U16 total_lcp_length)
{
	ppp_options_t 	*tmp_buf = (ppp_options_t *)rte_malloc(NULL,MSG_BUF*sizeof(char),0);
	ppp_options_t 	*tmp_cur = tmp_buf;
	int 			bool_flag = 0;
	U16 		tmp_total_length = 4;
	
	memset(tmp_buf, 0, MSG_BUF);
	rte_memcpy(tmp_buf, ppp_options, total_lcp_length-sizeof(ppp_header_t));

	ppp_hdr->length = sizeof(ppp_header_t);
	for(ppp_options_t *cur=ppp_options; tmp_total_length<total_lcp_length; cur=(ppp_options_t *)((char *)cur + cur->length)) {
		if (flag == CONFIG_NAK) {
			U8 len_byte = vrg_ccb->non_vlan_mode ? 0xD4 : 0xD0;
			if (cur->type == MRU && (cur->val[0] != 0x5 || cur->val[1] != len_byte)) {
				bool_flag = 1;
				VRG_LOG(WARN, vrg_ccb->fp, NULL, PPPLOGMSG, "MRU = %x%x", cur->val[0], cur->val[1]);
				cur->val[0] = 0x5;
				cur->val[1] = len_byte;
				rte_memcpy(tmp_cur,cur,cur->length);
				ppp_hdr->length += cur->length;
				tmp_cur = (ppp_options_t *)((char *)tmp_cur + cur->length);
			}
			else if (cur->type == AUTH) {
				U16 ppp_server_auth_method = cur->val[0] << 8 | cur->val[1];
				if (ppp_server_auth_method != auth_method) {
					/* if server wants to use pap or chap, then we just follow it */
					if (ppp_server_auth_method == PAP_PROTOCOL)
						auth_method = PAP_PROTOCOL;
					else if (ppp_server_auth_method == CHAP_PROTOCOL)
						auth_method = CHAP_PROTOCOL;
					else {
						bool_flag = 1;
						/* by default, we use pap auth */
						auth_method = PAP_PROTOCOL;
						cur->val[1] = auth_method & 0xff;
						cur->val[0] = (auth_method & 0xff00) >> 8;
						rte_memcpy(tmp_cur,cur,cur->length);
						ppp_hdr->length += cur->length;
						tmp_cur = (ppp_options_t *)((char *)tmp_cur + cur->length);
					}
				}
			}
		}
		else {
			if (cur->type != MAGIC_NUM && cur->type != MRU && cur->type != AUTH) {
				bool_flag= 1;
				rte_memcpy(tmp_cur,cur,cur->length);
				ppp_hdr->length += cur->length;
				tmp_cur = (ppp_options_t *)((char *)tmp_cur + cur->length);
			}
		}
		tmp_total_length += cur->length;
	}

	if (bool_flag == 1) {
		rte_memcpy(ppp_options,tmp_buf,ppp_hdr->length - sizeof(ppp_header_t));
		pppoe_header->length = rte_cpu_to_be_16((ppp_hdr->length) + sizeof(ppp_payload_t));
		ppp_hdr->length = rte_cpu_to_be_16(ppp_hdr->length);
		ppp_hdr->code = flag;
		rte_free(tmp_buf);

		return 1;
	}
	rte_free(tmp_buf);
	return 0;
}

/**
 * build_padi
 * 
 * @brief 
 * 		For build PPPoE init.
 * @param buffer 
 * 		The buffer to be processed by the codec.
 * @param s_ppp_ccb 
 * 		The ppp ccb.
 * @param len 
 * 		The length of the buffer.
 * @return 
 * 		void
 */
STATUS build_padi(U8 *buffer, U16 *mulen, PPP_INFO_t *s_ppp_ccb)
{
	struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)buffer;
	vlan_header_t		*vlan_header = (vlan_header_t *)(eth_hdr + 1);
	pppoe_header_t 		*pppoe_header = (pppoe_header_t *)(vlan_header + 1);
	pppoe_header_tag_t 	*pppoe_header_tag = (pppoe_header_tag_t *)(pppoe_header + 1);

	if (s_ppp_ccb->pppoe_phase.timer_counter >= s_ppp_ccb->pppoe_phase.max_retransmit) {
		VRG_LOG(ERR, vrg_ccb->fp, s_ppp_ccb, PPPLOGMSG, "User %" PRIu16 " timeout when sending PADI", s_ppp_ccb->user_num);
		return ERROR;
	}

	for(int i=0; i<RTE_ETHER_ADDR_LEN; i++) {
 		eth_hdr->src_addr.addr_bytes[i] = vrg_ccb->nic_info.hsi_wan_src_mac.addr_bytes[i];
 		eth_hdr->dst_addr.addr_bytes[i] = 0xff;
	}
	eth_hdr->ether_type = rte_cpu_to_be_16(VLAN);

	vlan_header->tci_union.tci_struct.priority = 0;
	vlan_header->tci_union.tci_struct.DEI = 0;
	vlan_header->tci_union.tci_struct.vlan_id = s_ppp_ccb->vlan;
	vlan_header->next_proto = rte_cpu_to_be_16(ETH_P_PPP_DIS);
	vlan_header->tci_union.tci_value = rte_cpu_to_be_16(vlan_header->tci_union.tci_value);

	pppoe_header->ver_type = VER_TYPE;
	pppoe_header->code = PADI;
	pppoe_header->session_id = 0; 

	pppoe_header_tag->type = rte_cpu_to_be_16(SERVICE_NAME); //padi tag type (service name)
	pppoe_header_tag->length = 0;

	pppoe_header->length = rte_cpu_to_be_16(sizeof(pppoe_header_tag_t));

	*mulen = sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t) + sizeof(pppoe_header_t) + sizeof(pppoe_header_tag_t);

	return SUCCESS;
}

/**
 * build_padr
 * 
 * @brief 
 * 		For build PPPoE request.
 * @param buffer 
 * 		The buffer to be processed by the codec.
 * @param s_ppp_ccb 
 * 		The ppp ccb.
 * @param len 
 * 		The length of the buffer.
 * @return 
 * 		void
 */
STATUS build_padr(U8 *buffer, U16 *mulen, PPP_INFO_t *s_ppp_ccb)
{
	//static unsigned char 		buffer[MSG_BUF];
	//static U16 			mulen;
	struct rte_ether_hdr 		*eth_hdr = (struct rte_ether_hdr *)buffer;
	vlan_header_t			*vlan_header = (vlan_header_t *)(eth_hdr + 1);
	pppoe_header_t 			*pppoe_header = (pppoe_header_t *)(vlan_header + 1);
	pppoe_header_tag_t 	*pppoe_header_tag = (pppoe_header_tag_t *)(pppoe_header + 1);

	if (s_ppp_ccb->pppoe_phase.timer_counter >= s_ppp_ccb->pppoe_phase.max_retransmit) {
		VRG_LOG(ERR, vrg_ccb->fp, s_ppp_ccb, PPPLOGMSG, "User %" PRIu16 "timeout when sending PADR", s_ppp_ccb->user_num);
		return ERROR;
	}

	rte_ether_addr_copy(&vrg_ccb->nic_info.hsi_wan_src_mac, &s_ppp_ccb->pppoe_phase.eth_hdr->src_addr);
	rte_ether_addr_copy(&s_ppp_ccb->PPP_dst_mac, &s_ppp_ccb->pppoe_phase.eth_hdr->dst_addr);
	s_ppp_ccb->pppoe_phase.pppoe_header->code = PADR;

 	U32 total_tag_length = 0;
	pppoe_header_tag_t *cur = s_ppp_ccb->pppoe_phase.pppoe_header_tag;
	pppoe_header_tag->length = 0;
	pppoe_header_tag->type = rte_cpu_to_be_16(SERVICE_NAME);
	pppoe_header_tag += 1;
	total_tag_length += sizeof(pppoe_header_tag_t);
	for(;;) {
		pppoe_header_tag->type = cur->type;
		pppoe_header_tag->length = cur->length;
		U16 tag_len = ntohs(cur->length);
		switch(ntohs(cur->type)) {
			case END_OF_LIST:
				break;
			case SERVICE_NAME:
				break;
			case AC_NAME:
				/* We dont need to add ac-name tag to PADR. */
				cur = (pppoe_header_tag_t *)((char *)cur + sizeof(pppoe_header_tag_t) + tag_len);
				continue;
			case HOST_UNIQ:
			case AC_COOKIE:
			case RELAY_ID:
				if (cur->length != 0) {
					rte_memcpy(pppoe_header_tag->value, cur->value, tag_len);
					total_tag_length = tag_len + sizeof(pppoe_header_tag_t) + total_tag_length;
				}
				break;
			case GENERIC_ERROR:
				VRG_LOG(ERR, vrg_ccb->fp, s_ppp_ccb, PPPLOGMSG, "PPPoE discover generic error.");
				return FALSE;
			default:
				VRG_LOG(WARN, vrg_ccb->fp, s_ppp_ccb, PPPLOGMSG, "Unknown PPPOE tag value.");
		}
		if (ntohs(cur->type) == END_OF_LIST)
			break;

		/* to caculate total pppoe header tags' length, we need to add tag type and tag length field in each tag scanning. */
		/* Fetch next tag field. */
		cur = (pppoe_header_tag_t *)((char *)cur + sizeof(pppoe_header_tag_t) + tag_len);
		pppoe_header_tag = (pppoe_header_tag_t *)((char *)pppoe_header_tag + sizeof(pppoe_header_tag_t) + tag_len);
	}

	s_ppp_ccb->pppoe_phase.pppoe_header->length = rte_cpu_to_be_16(total_tag_length);
	*mulen = sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t) + sizeof(pppoe_header_t) + total_tag_length;

	*eth_hdr = *(s_ppp_ccb->pppoe_phase.eth_hdr);
	*vlan_header = *(s_ppp_ccb->pppoe_phase.vlan_header);
	*pppoe_header = *(s_ppp_ccb->pppoe_phase.pppoe_header);

	return SUCCESS;
}

/**
 * build_padt
 * 
 * @brief 
 * 		For build PPPoE termination.
 * @param buffer 
 * 		The buffer to be processed by the codec.
 * @param s_ppp_ccb 
 * 		The ppp ccb.
 * @param len 
 * 		The length of the buffer.
 * @return 
 * 		void
 */
void build_padt(U8 *buffer, U16 *mulen, PPP_INFO_t *s_ppp_ccb)
{
	struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)buffer;
	vlan_header_t		*vlan_header = (vlan_header_t *)(eth_hdr + 1);
	pppoe_header_t 		*pppoe_header = (pppoe_header_t *)(vlan_header + 1);

	rte_ether_addr_copy(&vrg_ccb->nic_info.hsi_wan_src_mac, &eth_hdr->src_addr);
	rte_ether_addr_copy(&s_ppp_ccb->PPP_dst_mac, &eth_hdr->dst_addr);
	eth_hdr->ether_type = rte_cpu_to_be_16(VLAN);

	vlan_header->tci_union.tci_struct.priority = 0;
	vlan_header->tci_union.tci_struct.DEI = 0;
	vlan_header->tci_union.tci_struct.vlan_id = s_ppp_ccb->vlan;
	vlan_header->next_proto = rte_cpu_to_be_16(ETH_P_PPP_DIS);
	vlan_header->tci_union.tci_value = rte_cpu_to_be_16(vlan_header->tci_union.tci_value);

	pppoe_header->ver_type = VER_TYPE;
	pppoe_header->code = PADT;
	pppoe_header->session_id = s_ppp_ccb->session_id; 
	pppoe_header->length = 0;

	*mulen = sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t) + sizeof(pppoe_header_t);
}

/**
 * build_config_request
 * 
 * @brief 
 * 		For build PPP configure request, either in NCP or LCP phase.
 * @param buffer 
 * 		The buffer to be processed by the codec.
 * @param s_ppp_ccb 
 * 		The ppp ccb.
 * @param len 
 * 		The length of the buffer.
 * @return 
 * 		void
 */
void build_config_request(U8 *buffer, U16 *mulen, PPP_INFO_t *s_ppp_ccb)
{
	struct rte_ether_hdr 	*eth_hdr = (struct rte_ether_hdr *)buffer;
	vlan_header_t		*vlan_header = (vlan_header_t *)(eth_hdr + 1);
	pppoe_header_t 		*pppoe_header = (pppoe_header_t *)(vlan_header + 1);
	ppp_payload_t 		*ppp_payload = (ppp_payload_t *)(pppoe_header + 1);
	ppp_header_t 		*ppp_hdr = (ppp_header_t *)(ppp_payload + 1);
	ppp_options_t 		*ppp_options = (ppp_options_t *)(ppp_hdr + 1);

	rte_ether_addr_copy(&vrg_ccb->nic_info.hsi_wan_src_mac, &eth_hdr->src_addr);
	rte_ether_addr_copy(&s_ppp_ccb->PPP_dst_mac, &eth_hdr->dst_addr);
	
	eth_hdr->ether_type = rte_cpu_to_be_16(VLAN);

	vlan_header->tci_union.tci_struct.priority = 0;
	vlan_header->tci_union.tci_struct.DEI = 0;
	vlan_header->tci_union.tci_struct.vlan_id = s_ppp_ccb->vlan;
	vlan_header->next_proto = rte_cpu_to_be_16(ETH_P_PPP_SES);
	vlan_header->tci_union.tci_value = rte_cpu_to_be_16(vlan_header->tci_union.tci_value);

	/* build ppp protocol and lcp header. */
 	pppoe_header->ver_type = VER_TYPE;
 	pppoe_header->code = 0;
 	/* We don't convert seesion id to little endian at first */
 	pppoe_header->session_id = s_ppp_ccb->session_id; 

 	ppp_hdr->code = CONFIG_REQUEST;
	s_ppp_ccb->identifier = (s_ppp_ccb->identifier % UINT8_MAX) + 1;
 	ppp_hdr->identifier = s_ppp_ccb->identifier;

 	pppoe_header->length = sizeof(ppp_header_t) + sizeof(ppp_payload->ppp_protocol);
 	ppp_hdr->length = sizeof(ppp_header_t);

 	if (s_ppp_ccb->cp == 1) {
 		ppp_payload->ppp_protocol = rte_cpu_to_be_16(IPCP_PROTOCOL);
 		ppp_options->type = IP_ADDRESS;
 		rte_memcpy(ppp_options->val, &(s_ppp_ccb->hsi_ipv4), 4);
 		ppp_options->length = sizeof(s_ppp_ccb->hsi_ipv4) + sizeof(ppp_options_t);
 		pppoe_header->length += ppp_options->length;
 		ppp_hdr->length += ppp_options->length;
 	}
 	else if (s_ppp_ccb->cp == 0) {
 		ppp_payload->ppp_protocol = rte_cpu_to_be_16(LCP_PROTOCOL);
		ppp_options_t *cur = ppp_options;
		/* option, auth */
 		/*if (s_ppp_ccb->auth_method == PAP_PROTOCOL) {
 			cur->type = AUTH;
 			cur->length = 0x4;
 			U16 auth_pro = rte_cpu_to_be_16(PAP_PROTOCOL);
 			rte_memcpy(cur->val,&auth_pro,sizeof(U16));
 			pppoe_header->length += 4;
 			ppp_hdr->length += 4;

 			cur = (ppp_options_t *)((char *)(cur + 1) + sizeof(auth_pro));
 		}
		else if (s_ppp_ccb->auth_method == CHAP_PROTOCOL) {
			cur->type = AUTH;
 			cur->length = 0x5;
 			U16 auth_pro = rte_cpu_to_be_16(CHAP_PROTOCOL);
 			rte_memcpy(cur->val,&auth_pro,sizeof(U16));
			U8 auth_method = 0x5; // CHAP with MD5
			rte_memcpy((cur->val)+2,&auth_method,sizeof(U8));
 			pppoe_header->length += 5;
 			ppp_hdr->length += 5;

 			cur = (ppp_options_t *)((char *)(cur + 1) + sizeof(auth_pro) + sizeof(auth_method));
		}*/
 		/* options, max recv units */

 		cur->type = MRU;
 		cur->length = 0x4;
 		U16 max_recv_unit = rte_cpu_to_be_16(MAX_RECV);
 		rte_memcpy(cur->val,&max_recv_unit,sizeof(U16));
 		pppoe_header->length += 4;
 		ppp_hdr->length += 4;

 		cur = (ppp_options_t *)((char *)(cur + 1) + sizeof(max_recv_unit));
 		/* options, magic number */
 		cur->type = MAGIC_NUM;
 		cur->length = 0x6;
		*(U32 *)(cur->val) = s_ppp_ccb->magic_num;
 		pppoe_header->length += 6;
 		ppp_hdr->length += 6;
	}

	*mulen = pppoe_header->length + sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t) + sizeof(pppoe_header_t);

 	pppoe_header->length = rte_cpu_to_be_16(pppoe_header->length);
 	ppp_hdr->length = rte_cpu_to_be_16(ppp_hdr->length);
 	
	VRG_LOG(DBG, vrg_ccb->fp, s_ppp_ccb, PPPLOGMSG, "User %" PRIu16 " config request built.", s_ppp_ccb->user_num);
}

/**
 * build_config_ack
 *
 * @brief 
 * 		For build PPP config ack, either in NCP or LCP phase.
 * @param buffer 
 * 		The buffer to be processed by the codec.
 * @param s_ppp_ccb 
 * 		The ppp ccb.
 * @param len 
 * 		The length of the buffer.
 * @return 
 * 		void
 */
void build_config_ack(U8 *buffer, U16 *mulen, PPP_INFO_t *s_ppp_ccb)
{
	struct rte_ether_hdr 	*eth_hdr = (struct rte_ether_hdr *)buffer;
	vlan_header_t		*vlan_header = (vlan_header_t *)(eth_hdr + 1);
	pppoe_header_t 		*pppoe_header = (pppoe_header_t *)(vlan_header + 1);
	ppp_payload_t 		*ppp_payload = (ppp_payload_t *)(pppoe_header + 1);
	ppp_header_t 		*ppp_hdr = (ppp_header_t *)(ppp_payload + 1);
	ppp_options_t 		*ppp_options = (ppp_options_t *)(ppp_hdr + 1);
	
	*eth_hdr = *(s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].eth_hdr);
	rte_ether_addr_copy(&vrg_ccb->nic_info.hsi_wan_src_mac, &eth_hdr->src_addr);
	rte_ether_addr_copy(&s_ppp_ccb->PPP_dst_mac, &eth_hdr->dst_addr);

	*vlan_header = *(s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].vlan_header);
	*pppoe_header = *(s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].pppoe_header);
	*ppp_payload = *(s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].ppp_payload);
	*ppp_hdr = *(s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].ppp_hdr);
	ppp_hdr->code = CONFIG_ACK;
	rte_memcpy(ppp_options, s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].ppp_options, rte_cpu_to_be_16(ppp_hdr->length) - sizeof(ppp_header_t));

	*mulen = rte_be_to_cpu_16(pppoe_header->length) + sizeof(struct rte_ether_hdr) + sizeof(pppoe_header_t) + sizeof(vlan_header_t);

	VRG_LOG(DBG, vrg_ccb->fp, s_ppp_ccb, PPPLOGMSG, "User %" PRIu16 " config ack built.", s_ppp_ccb->user_num);
}

/**
 * build_config_nak_rej
 *
 * @brief 
 * 		For build PPP config reject and nak, either in NCP or LCP phase.
 * @param buffer 
 * 		The buffer to be processed by the codec.
 * @param s_ppp_ccb 
 * 		The ppp ccb.
 * @param len 
 * 		The length of the buffer.
 * @return 
 * 		void
 */
void build_config_nak_rej(U8 *buffer, U16 *mulen, PPP_INFO_t *s_ppp_ccb)
{
	struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)buffer;
	vlan_header_t		*vlan_header = (vlan_header_t *)(eth_hdr + 1);
	pppoe_header_t 		*pppoe_header = (pppoe_header_t *)(vlan_header + 1);
	ppp_payload_t 		*ppp_payload = (ppp_payload_t *)(pppoe_header + 1);
	ppp_header_t 		*ppp_hdr = (ppp_header_t *)(ppp_payload + 1);
	ppp_options_t 		*ppp_options = (ppp_options_t *)(ppp_hdr + 1);

	rte_ether_addr_copy(&vrg_ccb->nic_info.hsi_wan_src_mac, &eth_hdr->src_addr);
	rte_ether_addr_copy(&s_ppp_ccb->PPP_dst_mac, &eth_hdr->dst_addr);
	eth_hdr->ether_type = s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].eth_hdr->ether_type;

	*vlan_header = *(s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].vlan_header);
	*pppoe_header = *(s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].pppoe_header);
	*ppp_payload = *(s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].ppp_payload);
	*ppp_hdr = *(s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].ppp_hdr);

	*mulen = rte_be_to_cpu_16(pppoe_header->length) + sizeof(struct rte_ether_hdr) + sizeof(pppoe_header_t) + sizeof(vlan_header_t);

 	rte_memcpy(ppp_options, s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].ppp_options, rte_be_to_cpu_16(ppp_hdr->length) - sizeof(ppp_header_t));

	VRG_LOG(DBG, vrg_ccb->fp, s_ppp_ccb, PPPLOGMSG, "User %" PRIu16 " config nak/rej built.", s_ppp_ccb->user_num);
}

/**
 * build_echo_reply
 *
 * @brief 
 * 		For build PPP echo reply, only in LCP phase.
 * @param buffer 
 * 		The buffer to be processed by the codec.
 * @param s_ppp_ccb 
 * 		The ppp ccb.
 * @param len 
 * 		The length of the buffer.
 * @return 
 * 		void
 */
void build_echo_reply(U8 *buffer, U16 *mulen, PPP_INFO_t *s_ppp_ccb)
{
	struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)buffer;
	vlan_header_t		*vlan_header = (vlan_header_t *)(eth_hdr + 1);
	pppoe_header_t 		*pppoe_header = (pppoe_header_t *)(vlan_header + 1);
	ppp_payload_t 		*ppp_payload = (ppp_payload_t *)(pppoe_header + 1);
	ppp_header_t 		*ppp_hdr = (ppp_header_t *)(ppp_payload + 1);
	U8 *magic_num = (U8 *)(ppp_hdr + 1);
	U8 ppp_opt_len = rte_be_to_cpu_16(s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].ppp_hdr->length) - sizeof(ppp_header_t);

	rte_ether_addr_copy(&vrg_ccb->nic_info.hsi_wan_src_mac, &eth_hdr->src_addr);
	rte_ether_addr_copy(&s_ppp_ccb->PPP_dst_mac, &eth_hdr->dst_addr);
	eth_hdr->ether_type = s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].eth_hdr->ether_type;

	*vlan_header = *(s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].vlan_header);
	*pppoe_header = *(s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].pppoe_header);
	*ppp_payload = *(s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].ppp_payload);
	*ppp_hdr = *(s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].ppp_hdr);

	ppp_hdr->code = ECHO_REPLY;
	ppp_hdr->length = sizeof(ppp_header_t);
	pppoe_header->length = sizeof(ppp_payload_t) + sizeof(ppp_header_t);

	if (ppp_opt_len > 0) {
		*(U32 *)magic_num = s_ppp_ccb->magic_num;
		ppp_hdr->length += sizeof(s_ppp_ccb->magic_num);
		pppoe_header->length += sizeof(s_ppp_ccb->magic_num);
	}
	ppp_opt_len -= sizeof(s_ppp_ccb->magic_num);
	if (ppp_opt_len == sizeof(U32)/* echo requester's nmagic number */) {
		magic_num += sizeof(s_ppp_ccb->magic_num);
		*(U32 *)magic_num = *(U32 *)s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].ppp_options;
		ppp_hdr->length += ppp_opt_len;
		pppoe_header->length += ppp_opt_len;
	}

	*mulen = pppoe_header->length + sizeof(struct rte_ether_hdr) + sizeof(pppoe_header_t) + sizeof(vlan_header_t);
	ppp_hdr->length = rte_cpu_to_be_16(ppp_hdr->length);
	pppoe_header->length = rte_cpu_to_be_16(pppoe_header->length);
}

/**
 * build_terminate_ack
 *
 * @brief 
 * 		For build PPP terminate ack, either in NCP or LCP phase.
 * @param buffer 
 * 		The buffer to be processed by the codec.
 * @param s_ppp_ccb 
 * 		The ppp ccb.
 * @param len 
 * 		The length of the buffer.
 * @return 
 * 		void
 */
void build_terminate_ack(unsigned char* buffer, U16 *mulen, PPP_INFO_t *s_ppp_ccb)
{
	struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)buffer;
	vlan_header_t		*vlan_header = (vlan_header_t *)(eth_hdr + 1);
	pppoe_header_t 		*pppoe_header = (pppoe_header_t *)(vlan_header + 1);
	ppp_payload_t 		*ppp_payload = (ppp_payload_t *)(pppoe_header + 1);
	ppp_header_t 		*ppp_hdr = (ppp_header_t *)(ppp_payload + 1);

	rte_ether_addr_copy(&vrg_ccb->nic_info.hsi_wan_src_mac, &eth_hdr->src_addr);
	rte_ether_addr_copy(&s_ppp_ccb->PPP_dst_mac, &eth_hdr->dst_addr);
	eth_hdr->ether_type = s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].eth_hdr->ether_type;

	*vlan_header = *(s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].vlan_header);
	*pppoe_header = *(s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].pppoe_header);
	*ppp_payload = *(s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].ppp_payload);
	*ppp_hdr = *(s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].ppp_hdr);

	ppp_hdr->code = TERMIN_ACK;
	ppp_hdr->length = rte_cpu_to_be_16(sizeof(ppp_header_t));

	pppoe_header->length = rte_cpu_to_be_16(sizeof(ppp_header_t) + sizeof(ppp_payload_t));

	*mulen = rte_be_to_cpu_16(pppoe_header->length) + sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t) + sizeof(pppoe_header_t);
 	
	VRG_LOG(DBG, vrg_ccb->fp, s_ppp_ccb, PPPLOGMSG, "User %" PRIu16 " terminate ack built.", s_ppp_ccb->user_num);
}

/**
 * build_terminate_request
 *
 * @brief 
 * 		For build PPP terminate request, either in NCP or LCP phase.
 * @param buffer 
 * 		The buffer to be processed by the codec.
 * @param s_ppp_ccb 
 * 		The ppp ccb.
 * @param len 
 * 		The length of the buffer.
 * @return 
 * 		void
 */
void build_terminate_request(U8 *buffer, U16 *mulen, PPP_INFO_t *s_ppp_ccb)
{
	struct rte_ether_hdr 	*eth_hdr = (struct rte_ether_hdr *)buffer;
	vlan_header_t		*vlan_header = (vlan_header_t *)(eth_hdr + 1);
	pppoe_header_t 		*pppoe_header = (pppoe_header_t *)(vlan_header + 1);
	ppp_payload_t 		*ppp_payload = (ppp_payload_t *)(pppoe_header + 1);
	ppp_header_t 		*ppp_hdr = (ppp_header_t *)(ppp_payload + 1);

	rte_ether_addr_copy(&vrg_ccb->nic_info.hsi_wan_src_mac, &eth_hdr->src_addr);
	rte_ether_addr_copy(&s_ppp_ccb->PPP_dst_mac, &eth_hdr->dst_addr);
	eth_hdr->ether_type = rte_cpu_to_be_16(VLAN);

	vlan_header->tci_union.tci_struct.priority = 0;
	vlan_header->tci_union.tci_struct.DEI = 0;
	vlan_header->tci_union.tci_struct.vlan_id = s_ppp_ccb->vlan;
	vlan_header->next_proto = rte_cpu_to_be_16(ETH_P_PPP_SES);
	vlan_header->tci_union.tci_value = rte_cpu_to_be_16(vlan_header->tci_union.tci_value);
	/* build ppp protocol and lcp/ipcp header. */

 	pppoe_header->ver_type = VER_TYPE;
 	pppoe_header->code = 0;
 	/* We don't convert seesion id to little endian at first */
 	pppoe_header->session_id = s_ppp_ccb->session_id;

 	if (s_ppp_ccb->cp == 0) 
 		ppp_payload->ppp_protocol = rte_cpu_to_be_16(LCP_PROTOCOL);
 	else if (s_ppp_ccb->cp == 1)
 		ppp_payload->ppp_protocol = rte_cpu_to_be_16(IPCP_PROTOCOL);

 	ppp_hdr->code = TERMIN_REQUEST;
 	ppp_hdr->identifier = ((rand() % 254) + 1);

 	pppoe_header->length = sizeof(ppp_header_t) + sizeof(ppp_payload->ppp_protocol);
 	ppp_hdr->length = sizeof(ppp_header_t); 	


	*mulen = pppoe_header->length + sizeof(struct rte_ether_hdr) + sizeof(pppoe_header_t) + sizeof(vlan_header_t);
 	pppoe_header->length = rte_cpu_to_be_16(pppoe_header->length);
 	ppp_hdr->length = rte_cpu_to_be_16(ppp_hdr->length);
 	
	VRG_LOG(DBG, vrg_ccb->fp, s_ppp_ccb, PPPLOGMSG, "User %" PRIu16 " terminate request built.", s_ppp_ccb->user_num);
}

STATUS build_code_reject(__attribute__((unused)) unsigned char* buffer, __attribute__((unused)) PPP_INFO_t *s_ppp_ccb, __attribute__((unused)) U16 *mulen)
{
	puts("build code reject.");

	return TRUE;
}

/**
 * build_auth_request_pap
 *
 * @brief 
 * 		For PAP auth, send after LCP nego complete.
 * @param buffer 
 * 		The buffer to be processed by the codec.
 * @param s_ppp_ccb 
 * 		The ppp ccb.
 * @param len 
 * 		The length of the buffer.
 * @return 
 * 		void
 */
void build_auth_request_pap(unsigned char* buffer, U16 *mulen, PPP_INFO_t *s_ppp_ccb)
{
    struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)buffer;
    vlan_header_t		*vlan_header = (vlan_header_t *)(eth_hdr + 1);
    pppoe_header_t 		*pppoe_header = (pppoe_header_t *)(vlan_header + 1);
    ppp_payload_t 		*ppp_payload = (ppp_payload_t *)(pppoe_header + 1);
	ppp_header_t        *ppp_pap_header = (ppp_header_t *)(ppp_payload + 1);
	U8                  peer_id_length = strlen((const char *)(s_ppp_ccb->ppp_user_id));
	U8                  peer_passwd_length = strlen((const char *)(s_ppp_ccb->ppp_passwd));
    U8                  *pap_account = (U8 *)(ppp_pap_header + 1);
    U8                  *pap_password = pap_account + peer_id_length + sizeof(U8)/* pap account length field */;

	s_ppp_ccb->phase = AUTH_PHASE;

	rte_ether_addr_copy(&vrg_ccb->nic_info.hsi_wan_src_mac, &eth_hdr->src_addr);
	rte_ether_addr_copy(&s_ppp_ccb->PPP_dst_mac, &eth_hdr->dst_addr);
    eth_hdr->ether_type = rte_cpu_to_be_16(VLAN);

    *vlan_header = *(s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].vlan_header);
    *pppoe_header = *(s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].pppoe_header);
    ppp_payload->ppp_protocol = rte_cpu_to_be_16(PAP_PROTOCOL);

	ppp_pap_header->code = PAP_REQUEST;
	ppp_pap_header->identifier = s_ppp_ccb->identifier;

    *(U8 *)pap_account = peer_id_length;
    rte_memcpy(pap_account + sizeof(U8), s_ppp_ccb->ppp_user_id, peer_id_length);
    *(U8 *)pap_password = peer_passwd_length;
    rte_memcpy(pap_password + sizeof(U8), s_ppp_ccb->ppp_passwd, peer_passwd_length);

	ppp_pap_header->length = 2 * sizeof(U8)/* for pap account length and pap password length */ 
    + peer_id_length + peer_passwd_length + sizeof(ppp_header_t);
	pppoe_header->length = ppp_pap_header->length + sizeof(ppp_payload_t);
	ppp_pap_header->length = rte_cpu_to_be_16(ppp_pap_header->length);
	pppoe_header->length = rte_cpu_to_be_16(pppoe_header->length);

	*mulen = ntohs(pppoe_header->length) + sizeof(struct rte_ether_hdr) + sizeof(pppoe_header_t) + sizeof(vlan_header_t);
 	
	VRG_LOG(DBG, vrg_ccb->fp, s_ppp_ccb, PPPLOGMSG, "User %" PRIu16 " pap request built.", s_ppp_ccb->user_num);
}

/**
 * build_auth_ack_pap
 *
 * @brief 
 * 		For Spirent test center, in pap, we will receive pap request packet.
 * @param buffer 
 * 		The buffer to be processed by the codec.
 * @param s_ppp_ccb 
 * 		The ppp ccb.
 * @param len 
 * 		The length of the buffer.
 * @return 
 * 		void
 */
void build_auth_ack_pap(unsigned char *buffer, U16 *mulen, PPP_INFO_t *s_ppp_ccb)
{
	const char 			*login_msg = "Login ok";
    struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)buffer;
    vlan_header_t		*vlan_header = (vlan_header_t *)(eth_hdr + 1);
    pppoe_header_t 		*pppoe_header = (pppoe_header_t *)(vlan_header + 1);
    ppp_payload_t 		*ppp_payload = (ppp_payload_t *)(pppoe_header + 1);
    ppp_header_t        *ppp_pap_header = (ppp_header_t *)(ppp_payload + 1);
    ppp_pap_ack_nak_t 	*ppp_pap_ack_nak = (ppp_pap_ack_nak_t *)(ppp_pap_header + 1);

    rte_ether_addr_copy(&vrg_ccb->nic_info.hsi_wan_src_mac, &eth_hdr->src_addr);
	rte_ether_addr_copy(&s_ppp_ccb->PPP_dst_mac, &eth_hdr->dst_addr);
    eth_hdr->ether_type = rte_cpu_to_be_16(VLAN);

    *vlan_header = *(s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].vlan_header);
    *pppoe_header = *(s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].pppoe_header);
    ppp_payload->ppp_protocol = rte_cpu_to_be_16(PAP_PROTOCOL);

	ppp_pap_header->code = PAP_ACK;
	ppp_pap_header->identifier = s_ppp_ccb->identifier;

	ppp_pap_ack_nak->msg_length = strlen(login_msg);
	rte_memcpy(ppp_pap_ack_nak->msg, login_msg, ppp_pap_ack_nak->msg_length);

	ppp_pap_header->length = sizeof(ppp_header_t) + ppp_pap_ack_nak->msg_length + sizeof(ppp_pap_ack_nak->msg_length);
	pppoe_header->length = ppp_pap_header->length + sizeof(ppp_payload_t);
    *mulen = pppoe_header->length + sizeof(struct rte_ether_hdr) + sizeof(pppoe_header_t) + sizeof(vlan_header_t);

	ppp_pap_header->length = rte_cpu_to_be_16(ppp_pap_header->length);
	pppoe_header->length = rte_cpu_to_be_16(pppoe_header->length);
 	
	VRG_LOG(DBG, vrg_ccb->fp, s_ppp_ccb, PPPLOGMSG, "User %" PRIu16 " pap ack built.", s_ppp_ccb->user_num);
}

/* TODO: not yet tested */
/**
 * @brief build_auth_request_chap
 * For CHAP auth, starting after LCP nego complete.
 * 
 * @param buffer ppp pkt buffer
 * @param s_ppp_ccb 
 * @param mulen ppp pkt buffer length
 * @retval TRUE if encode successfully
 * @retval FALSE if encode failed 
 */
STATUS build_auth_response_chap(U8 *buffer, PPP_INFO_t *s_ppp_ccb, U16 *mulen, ppp_chap_data_t *ppp_chap_data)
{
	U8 chap_hash[16];
	U8 *buf_ptr = buffer;
	ppp_chap_data_t new_ppp_chap_data;
	struct rte_ether_addr tmp_mac;
	
	MD5_CTX  context;
    
	MD5Init(&context);
	MD5Update(&context, &s_ppp_ccb->ppp_phase[0].ppp_hdr->identifier, 1);
	MD5Update(&context, s_ppp_ccb->ppp_passwd, strlen((const char *)s_ppp_ccb->ppp_passwd));
	MD5Update(&context, ppp_chap_data->val, ppp_chap_data->val_size);
	MD5Final(chap_hash, &context);
	new_ppp_chap_data.val_size = 16;
	new_ppp_chap_data.val = chap_hash;
	new_ppp_chap_data.name = s_ppp_ccb->ppp_user_id;

	rte_ether_addr_copy(&s_ppp_ccb->ppp_phase[0].eth_hdr->src_addr, &tmp_mac);
	rte_ether_addr_copy(&s_ppp_ccb->ppp_phase[0].eth_hdr->dst_addr, &s_ppp_ccb->ppp_phase[0].eth_hdr->src_addr);
	rte_ether_addr_copy(&tmp_mac, &s_ppp_ccb->ppp_phase[0].eth_hdr->dst_addr);

	*(struct rte_ether_hdr *)buf_ptr = *s_ppp_ccb->ppp_phase[0].eth_hdr;
	buf_ptr += sizeof(struct rte_ether_hdr);
	*(vlan_header_t *)buf_ptr = *s_ppp_ccb->ppp_phase[0].vlan_header;
	buf_ptr += sizeof(vlan_header_t);
	*(pppoe_header_t *)buf_ptr = *s_ppp_ccb->ppp_phase[0].pppoe_header;
	buf_ptr += sizeof(pppoe_header_t);
	*(ppp_payload_t *)buf_ptr = *s_ppp_ccb->ppp_phase[0].ppp_payload;
	buf_ptr += sizeof(ppp_payload_t);
	s_ppp_ccb->ppp_phase[0].ppp_hdr->code = CHAP_RESPONSE;
	s_ppp_ccb->ppp_phase[0].ppp_hdr->length = sizeof(ppp_header_t) + 1 + 16 + strlen((const char *)new_ppp_chap_data.name);
	*(ppp_header_t *)buf_ptr = *s_ppp_ccb->ppp_phase[0].ppp_hdr;
	buf_ptr += sizeof(ppp_header_t);
	((ppp_chap_data_t *)buf_ptr)->val_size = new_ppp_chap_data.val_size;
	memcpy(((ppp_chap_data_t *)buf_ptr)->val, new_ppp_chap_data.val, new_ppp_chap_data.val_size);
 	memcpy(((ppp_chap_data_t *)buf_ptr)->name, new_ppp_chap_data.name, strlen((const char *)new_ppp_chap_data.name));
	buf_ptr += 1 + 16 + strlen((const char *)new_ppp_chap_data.name);
	*mulen = buf_ptr - buffer;

	VRG_LOG(DBG, vrg_ccb->fp, s_ppp_ccb, PPPLOGMSG, "User %" PRIu16 " chap response built.", s_ppp_ccb->user_num);
 	return TRUE;
}

STATUS send_pkt(U8 encode_type, PPP_INFO_t *s_ppp_ccb)
{
	U8 buffer[MSG_BUF];
	U16 mulen = 0;

	switch (encode_type) {
	case ENCODE_PADI:
		if (build_padi(buffer, &mulen, s_ppp_ccb) == ERROR) {
			PPP_bye(s_ppp_ccb);
			return ERROR;
		}
		s_ppp_ccb->pppoe_phase.timer_counter++;
		drv_xmit(vrg_ccb, buffer, mulen);
		break;
	case ENCODE_PADR:
		if (build_padr(buffer, &mulen, s_ppp_ccb) == ERROR) {
			PPP_bye(s_ppp_ccb);
			return ERROR;
		}
		s_ppp_ccb->pppoe_phase.timer_counter++;
		drv_xmit(vrg_ccb, buffer, mulen);
		break;
	case ENCODE_PADT:
		build_padt(buffer, &mulen, s_ppp_ccb);
		drv_xmit(vrg_ccb, buffer, mulen);
		s_ppp_ccb->phase = PPPOE_PHASE;
		s_ppp_ccb->pppoe_phase.active = FALSE;
		VRG_LOG(DBG, vrg_ccb->fp, s_ppp_ccb, PPPLOGMSG, "User %u PPPoE session closed successfully.", s_ppp_ccb->user_num);
		PPP_bye(s_ppp_ccb);
		break;
	default:
		return ERROR;
	}

	return SUCCESS;
}

void codec_init(VRG_t *ccb)
{
	vrg_ccb = ccb;
}
