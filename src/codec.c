#include "codec.h"
#include "dbg.h"
#include "vrg.h"
#include <rte_timer.h>
#include <rte_ether.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_log.h>
#include <rte_byteorder.h>
#include <cmdline_socket.h>

extern STATUS PPP_FSM(struct rte_timer *ppp, PPP_INFO_t *s_ppp_ccb, U16 event);

extern struct rte_ring 		*rte_ring, *gateway_q, *uplink_q, *downlink_q;
extern struct rte_ether_addr wan_mac;
extern struct cmdline 		*cl;
extern struct lcore_map 	lcore;
extern FILE					*fp;
extern BOOL					quit_flag;

U16 auth_method;

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

	if (mail->len > ETH_MTU){
	    VRG_LOG(INFO, NULL, s_ppp_ccb, PPPLOGMSG, "error! too large frame(%d)\n", mail->len);
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
								RTE_LOG(INFO,EAL,"Session 0x%x recv ppp LCP magic number error.\n", rte_cpu_to_be_16(s_ppp_ccb->session_id));
								#ifdef _DP_DBG
								puts("recv ppp LCP magic number error");
								#endif
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
				return TRUE;
			case CONFIG_REJECT :
				*event = E_RECV_CONFIG_NAK_REJ;
				RTE_LOG(INFO, EAL, "User %" PRIu16 " recv LCP reject message with option %x.\n", s_ppp_ccb->user_num, ppp_options->type);
				#ifdef _DP_DBG
				printf("recv LCP reject message with option %x\n", ppp_options->type);
				#endif
				if (ppp_options->type == AUTH) {
					if (s_ppp_ccb->is_pap_auth == FALSE)
						return ERROR;
					s_ppp_ccb->is_pap_auth = FALSE;
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
		ppp_pap_ack_nak_t ppp_pap_ack_nak, *tmp_ppp_pap_ack_nak = (ppp_pap_ack_nak_t *)(tmp_ppp_hdr + 1);
		rte_memcpy(&ppp_pap_ack_nak,tmp_ppp_pap_ack_nak,tmp_ppp_pap_ack_nak->msg_length + sizeof(U8));
		if (ppp_hdr->code == PAP_ACK) {
			RTE_LOG(INFO, EAL, "User %" PRIu16 " auth success.\n", s_ppp_ccb->user_num);
			#ifdef _DP_DBG
			puts("auth success.");
			#endif
			s_ppp_ccb->phase = IPCP_PHASE;
			return TRUE;
		}
		else if (ppp_hdr->code == PAP_NAK) {
    		s_ppp_ccb->phase = LCP_PHASE;
    		PPP_FSM(&(s_ppp_ccb->ppp),s_ppp_ccb,E_CLOSE);
			RTE_LOG(INFO, EAL, "User %" PRIu16 " auth fail.\n", s_ppp_ccb->user_num);
			#ifdef _DP_DBG
			puts("auth fail.");
			#endif
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
			if (build_auth_ack_pap(buffer, &tmp_s_ppp_ccb, &mulen) < 0)
				return ERROR;
				
			drv_xmit(buffer,mulen);
			RTE_LOG(INFO, EAL, "User %" PRIu16 " recv pap request.\n", s_ppp_ccb->user_num);
			#ifdef _DP_DBG
			puts("recv pap request");
			#endif
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
				
			drv_xmit(buffer,mulen);
			RTE_LOG(INFO, EAL, "User %" PRIu16 " recv chap challenge.\n", s_ppp_ccb->user_num);
			#ifdef _DP_DBG
			puts("recv chap chapllenge");
			#endif
			return TRUE;
		}
		else if (ppp_hdr->code == CHAP_SUCCESS) {
			RTE_LOG(INFO, EAL, "User %" PRIu16 " auth success.\n", s_ppp_ccb->user_num);
			#ifdef _DP_DBG
			puts("auth success.");
			#endif
			s_ppp_ccb->phase = IPCP_PHASE;
			return TRUE;
		}
		else if (ppp_hdr->code == CHAP_FAILURE) {
    		s_ppp_ccb->phase = LCP_PHASE;
			RTE_LOG(INFO, EAL, "User %" PRIu16 " auth fail.\n", s_ppp_ccb->user_num);
			#ifdef _DP_DBG
			puts("auth fail.");
			#endif
			return TRUE;
		}
	}
	else {
		RTE_LOG(INFO, EAL, "User %" PRIu16 " recv unknown PPP protocol.\n", s_ppp_ccb->user_num);
		#ifdef _DP_DBG
		puts("unknown PPP protocol");
		#endif
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
			RTE_LOG(INFO, EAL, "User %" PRIu16 " vlan 0x%x recv termin ack.\n", s_ppp_ccb->user_num, s_ppp_ccb->vlan);
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
			#ifdef _NON_VLAN
			if (cur->type == MRU && (cur->val[0] != 0x5 || cur->val[1] != 0xD4)) {
			#else
			if (cur->type == MRU && (cur->val[0] != 0x5 || cur->val[1] != 0xD0)) {
			#endif
				bool_flag = 1;
				cur->val[0] = 0x5;
				#ifdef _NON_VLAN
				cur->val[1] = 0xD4;
				#else
				cur->val[1] = 0xD0;
				#endif
				rte_memcpy(tmp_cur,cur,cur->length);
				ppp_hdr->length += cur->length;
				tmp_cur = (ppp_options_t *)((char *)tmp_cur + cur->length);
			}
			else if (cur->type == AUTH) {
				if (((auth_method & 0xff) != cur->val[1]) || (((auth_method & 0xff00) >> 8) != cur->val[0])) {
					cur->val[1] = auth_method & 0xff;
					cur->val[0] = (auth_method & 0xff00) >> 8;
					rte_memcpy(tmp_cur,cur,cur->length);
					ppp_hdr->length += cur->length;
					tmp_cur = (ppp_options_t *)((char *)tmp_cur + cur->length);
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
 * purpose: For build PPPoE init and send.
 * input: 	*s_ppp_ccb
 * 			*time - PPPoE timer
 * output: 	TRUE/FALSE
 */
STATUS build_padi(__attribute__((unused)) struct rte_timer *tim, PPP_INFO_t *s_ppp_ccb)
{
	unsigned char 		buffer[MSG_BUF];
	U16 			mulen;
	struct rte_ether_hdr 	eth_hdr;
	vlan_header_t		vlan_header;
	pppoe_header_t 		pppoe_header;
	pppoe_header_tag_t 	pppoe_header_tag;

	if (s_ppp_ccb->pppoe_phase.timer_counter >= s_ppp_ccb->pppoe_phase.max_retransmit) {
		RTE_LOG(INFO,EAL,"User %" PRIu16 " timeout when sending PADI\n", s_ppp_ccb->user_num);
		#ifdef _DP_DBG
		puts("timeout when sending PADI");
		#endif
		PPP_bye(s_ppp_ccb);
	}
	for(int i=0; i<6; i++) {
 		eth_hdr.src_addr.addr_bytes[i] = vrg_ccb.hsi_wan_src_mac.addr_bytes[i];
 		eth_hdr.dst_addr.addr_bytes[i] = 0xff;
	}
	eth_hdr.ether_type = rte_cpu_to_be_16(VLAN);

	vlan_header.tci_union.tci_struct.priority = 0;
	vlan_header.tci_union.tci_struct.DEI = 0;
	vlan_header.tci_union.tci_struct.vlan_id = s_ppp_ccb->vlan;
	vlan_header.next_proto = rte_cpu_to_be_16(ETH_P_PPP_DIS);
	vlan_header.tci_union.tci_value = rte_cpu_to_be_16(vlan_header.tci_union.tci_value);

	pppoe_header.ver_type = VER_TYPE;
	pppoe_header.code = PADI;
	pppoe_header.session_id = 0; 

	pppoe_header_tag.type = rte_cpu_to_be_16(SERVICE_NAME); //padi tag type (service name)
	pppoe_header_tag.length = 0;

	pppoe_header.length = rte_cpu_to_be_16(sizeof(pppoe_header_tag_t));

	mulen = sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t) + sizeof(pppoe_header_t) + sizeof(pppoe_header_tag_t);

	rte_memcpy(buffer,&eth_hdr,sizeof(struct rte_ether_hdr));
	rte_memcpy(buffer+sizeof(struct rte_ether_hdr),&vlan_header,sizeof(vlan_header_t));
	rte_memcpy(buffer+sizeof(struct rte_ether_hdr)+sizeof(vlan_header_t),&pppoe_header,sizeof(pppoe_header_t));
	rte_memcpy(buffer+sizeof(struct rte_ether_hdr)+sizeof(vlan_header_t)+sizeof(pppoe_header_t),&pppoe_header_tag,sizeof(pppoe_header_tag_t));
	drv_xmit(buffer,mulen);
	s_ppp_ccb->pppoe_phase.timer_counter++;

	return TRUE;
}

/**
 * build_padr
 *
 * purpose: For build PPPoE request and send.
 * input: 	*s_ppp_ccb
 * 			*time - PPPoE timer
 * output: 	TRUE/FALSE
 */
STATUS build_padr(__attribute__((unused)) struct rte_timer *tim, PPP_INFO_t *s_ppp_ccb)
{
	static unsigned char 		buffer[MSG_BUF];
	static U16 			mulen;
	pppoe_header_tag_t 	*tmp_pppoe_header_tag = (pppoe_header_tag_t *)((pppoe_header_t *)((vlan_header_t *)((struct rte_ether_hdr *)buffer + 1) + 1) + 1);

	if (s_ppp_ccb->pppoe_phase.timer_counter >= s_ppp_ccb->pppoe_phase.max_retransmit) {
		RTE_LOG(INFO,EAL,"User %" PRIu16 "timeout when sending PADR\n", s_ppp_ccb->user_num);
		#ifdef _DP_DBG
		puts("timeout when sending PADR");
		#endif
		PPP_bye(s_ppp_ccb);
	}
	if (s_ppp_ccb->pppoe_phase.timer_counter > 0)
		goto send;
	rte_ether_addr_copy(&vrg_ccb.hsi_wan_src_mac, &s_ppp_ccb->pppoe_phase.eth_hdr->src_addr);
	rte_ether_addr_copy(&s_ppp_ccb->PPP_dst_mac, &s_ppp_ccb->pppoe_phase.eth_hdr->dst_addr);
	s_ppp_ccb->pppoe_phase.pppoe_header->code = PADR;

 	U32 total_tag_length = 0;
	for(pppoe_header_tag_t *cur = tmp_pppoe_header_tag;;) {
		cur->type = s_ppp_ccb->pppoe_phase.pppoe_header_tag->type;
		cur->length = s_ppp_ccb->pppoe_phase.pppoe_header_tag->length;
		switch(ntohs(s_ppp_ccb->pppoe_phase.pppoe_header_tag->type)) {
			case END_OF_LIST:
				break;
			case SERVICE_NAME:
				break;
			case AC_NAME:
				/* We dont need to add ac-name tag to PADR. */
				s_ppp_ccb->pppoe_phase.pppoe_header_tag = (pppoe_header_tag_t *)((char *)(s_ppp_ccb->pppoe_phase.pppoe_header_tag) + 4 + ntohs(s_ppp_ccb->pppoe_phase.pppoe_header_tag->length));
				continue;
			case HOST_UNIQ:
			case AC_COOKIE:
			case RELAY_ID:
				if (cur->length != 0)
					rte_memcpy(cur->value,s_ppp_ccb->pppoe_phase.pppoe_header_tag->value,ntohs(cur->length));
				break;
			case GENERIC_ERROR:
				RTE_LOG(INFO,EAL,"PPPoE discover generic error.\n");
				#ifdef _DP_DBG
				puts("PPPoE discover generic error");
				#endif
				return FALSE;
			default:
				RTE_LOG(INFO,EAL,"Unknown PPPOE tag value\n");
				#ifdef _DP_DBG
				puts("Unknown PPPOE tag value"); 
				#endif
		}
		if (ntohs(s_ppp_ccb->pppoe_phase.pppoe_header_tag->type) == END_OF_LIST)
			break;

		/* to caculate total pppoe header tags' length, we need to add tag type and tag length field in each tag scanning. */
		total_tag_length = ntohs(cur->length) + 4 + total_tag_length;
		/* Fetch next tag field. */
		s_ppp_ccb->pppoe_phase.pppoe_header_tag = (pppoe_header_tag_t *)((char *)(s_ppp_ccb->pppoe_phase.pppoe_header_tag) + 4 + ntohs(s_ppp_ccb->pppoe_phase.pppoe_header_tag->length));
		cur = (pppoe_header_tag_t *)((char *)cur + 4 + ntohs(cur->length));
	}

	s_ppp_ccb->pppoe_phase.pppoe_header->length = rte_cpu_to_be_16(total_tag_length);
	mulen = sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t) + sizeof(pppoe_header_t) + total_tag_length;

	rte_memcpy(buffer,s_ppp_ccb->pppoe_phase.eth_hdr,sizeof(struct rte_ether_hdr));
	rte_memcpy(buffer+sizeof(struct rte_ether_hdr),s_ppp_ccb->pppoe_phase.vlan_header,sizeof(vlan_header_t));
	rte_memcpy(buffer+sizeof(struct rte_ether_hdr)+sizeof(vlan_header_t),s_ppp_ccb->pppoe_phase.pppoe_header,sizeof(pppoe_header_t));
	rte_memcpy(buffer+sizeof(struct rte_ether_hdr)+sizeof(vlan_header_t)+sizeof(pppoe_header_t),tmp_pppoe_header_tag,total_tag_length);
send:
	drv_xmit(buffer,mulen);
	s_ppp_ccb->pppoe_phase.timer_counter++;

	return TRUE;
}

/**
 * build_padt
 *
 * purpose: For build PPPoE terminate and send.
 * input: 	*s_ppp_ccb
 * output: 	TRUE/FALSE
 */
STATUS build_padt(PPP_INFO_t *s_ppp_ccb)
{
	unsigned char 		buffer[MSG_BUF];
	U16 			mulen;
	struct rte_ether_hdr 	eth_hdr;
	vlan_header_t		vlan_header;
	pppoe_header_t 		pppoe_header;

	rte_ether_addr_copy(&vrg_ccb.hsi_wan_src_mac, &eth_hdr.src_addr);
	rte_ether_addr_copy(&s_ppp_ccb->PPP_dst_mac, &eth_hdr.dst_addr);
	eth_hdr.ether_type = rte_cpu_to_be_16(VLAN);

	vlan_header.tci_union.tci_struct.priority = 0;
	vlan_header.tci_union.tci_struct.DEI = 0;
	vlan_header.tci_union.tci_struct.vlan_id = s_ppp_ccb->vlan;
	vlan_header.next_proto = rte_cpu_to_be_16(ETH_P_PPP_DIS);
	vlan_header.tci_union.tci_value = rte_cpu_to_be_16(vlan_header.tci_union.tci_value);

	pppoe_header.ver_type = VER_TYPE;
	pppoe_header.code = PADT;
	pppoe_header.session_id = s_ppp_ccb->session_id; 
	pppoe_header.length = 0;

	mulen = sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t) + sizeof(pppoe_header_t);

	rte_memcpy(buffer,&eth_hdr,sizeof(struct rte_ether_hdr));
	rte_memcpy(buffer+sizeof(struct rte_ether_hdr),&vlan_header,sizeof(vlan_header_t));
	rte_memcpy(buffer+sizeof(struct rte_ether_hdr)+sizeof(vlan_header_t),&pppoe_header,sizeof(pppoe_header_t));
	drv_xmit(buffer,mulen);

	s_ppp_ccb->phase = PPPOE_PHASE;
	s_ppp_ccb->pppoe_phase.active = FALSE;
	printf("User %u PPPoE session closed successfully\nvRG> ", s_ppp_ccb->user_num);

	PPP_bye(s_ppp_ccb);

	return TRUE;
}

/**
 * build_config_request
 *
 * purpose: For build PPP configure request, either in NCP or LCP phase.
 * input: 	*buffer - packet buffer,
 * 		    *s_ppp_ccb,
 * 			*mulen - packet length
 * output: 	TRUE/FALSE
 * return: 	packet buffer
 */
STATUS build_config_request(unsigned char *buffer, PPP_INFO_t *s_ppp_ccb, U16 *mulen)
{
	struct rte_ether_hdr 	*eth_hdr = s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].eth_hdr;
	vlan_header_t		*vlan_header = s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].vlan_header;
	pppoe_header_t 		*pppoe_header = s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].pppoe_header;
	ppp_payload_t 		*ppp_payload = s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].ppp_payload;
	ppp_header_t 		*ppp_hdr = s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].ppp_hdr;
	ppp_options_t 		*ppp_options = s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].ppp_options;

	srand(time(NULL));

	rte_ether_addr_copy(&vrg_ccb.hsi_wan_src_mac, &eth_hdr->src_addr);
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
 	ppp_hdr->identifier = ((rand() % 254) + 1);

 	s_ppp_ccb->identifier = ppp_hdr->identifier;

 	pppoe_header->length = sizeof(ppp_header_t) + sizeof(ppp_payload->ppp_protocol);
 	ppp_hdr->length = sizeof(ppp_header_t);

 	if (s_ppp_ccb->cp == 1) {
 		ppp_payload->ppp_protocol = rte_cpu_to_be_16(IPCP_PROTOCOL);
 		ppp_options->type = IP_ADDRESS;
 		rte_memcpy(ppp_options->val,&(s_ppp_ccb->hsi_ipv4),4);
 		ppp_options->length = sizeof(s_ppp_ccb->hsi_ipv4) + sizeof(ppp_options_t);
 		pppoe_header->length += ppp_options->length;
 		ppp_hdr->length += ppp_options->length;
 	}
 	else if (s_ppp_ccb->cp == 0) {
 		ppp_payload->ppp_protocol = rte_cpu_to_be_16(LCP_PROTOCOL);
 		/* options, max recv units */
 		ppp_options_t *cur = ppp_options;

 		cur->type = MRU;
 		cur->length = 0x4;
 		U16 max_recv_unit = rte_cpu_to_be_16(MAX_RECV);
 		rte_memcpy(cur->val,&max_recv_unit,sizeof(U16));
 		pppoe_header->length += 4;
 		ppp_hdr->length += 4;

 		cur = (ppp_options_t *)((char *)(cur + 1) + sizeof(max_recv_unit));
 		/* option, auth */
 		if (s_ppp_ccb->auth_method == PAP_PROTOCOL) {
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
			rte_memcpy(cur->val,&auth_method,sizeof(U8));
 			pppoe_header->length += 5;
 			ppp_hdr->length += 5;

 			cur = (ppp_options_t *)((char *)(cur + 1) + sizeof(auth_pro) + sizeof(auth_method));
		}
 		/* options, magic number */
 		cur->type = MAGIC_NUM;
 		cur->length = 0x6;
 		s_ppp_ccb->magic_num = rte_cpu_to_be_32((rand() % 0xFFFFFFFE) + 1);
 		rte_memcpy(cur->val,&(s_ppp_ccb->magic_num),sizeof(U32));
 		pppoe_header->length += 6;
 		ppp_hdr->length += 6;
	}

	*mulen = pppoe_header->length + sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t) + sizeof(pppoe_header_t);

 	pppoe_header->length = rte_cpu_to_be_16(pppoe_header->length);
 	ppp_hdr->length = rte_cpu_to_be_16(ppp_hdr->length);
 	memset(buffer,0,MSG_BUF);
 	rte_memcpy(buffer,eth_hdr,14);
	rte_memcpy(buffer+14,vlan_header,sizeof(vlan_header_t));
 	rte_memcpy(buffer+14+sizeof(vlan_header_t),pppoe_header,sizeof(pppoe_header_t));
 	rte_memcpy(buffer+14+sizeof(vlan_header_t)+sizeof(pppoe_header_t),ppp_payload,sizeof(ppp_payload_t));
 	rte_memcpy(buffer+14+sizeof(vlan_header_t)+sizeof(pppoe_header_t)+sizeof(ppp_payload_t),ppp_hdr,sizeof(ppp_header_t));
 	rte_memcpy(buffer+14+sizeof(vlan_header_t)+sizeof(pppoe_header_t)+sizeof(ppp_payload_t)+sizeof(ppp_header_t),ppp_options,rte_cpu_to_be_16(ppp_hdr->length) - sizeof(ppp_header_t));

	RTE_LOG(INFO,EAL,"User %" PRIu16 " config request built.\n", s_ppp_ccb->user_num);
	#ifdef _DP_DBG
 	puts("config request built.");
	#endif
 	return TRUE;
}

/**
 * build_config_ack
 *
 * purpose: For build PPP configure ack, either in NCP or LCP phase.
 * input: 	*buffer - packet buffer,
 * 		    *s_ppp_ccb,
 * 			*mulen - packet length
 * output: 	TRUE/FALSE
 * return: 	packet buffer
 */
STATUS build_config_ack(unsigned char* buffer, PPP_INFO_t *s_ppp_ccb, U16 *mulen)
{
	struct rte_ether_hdr 	*eth_hdr = s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].eth_hdr;
	vlan_header_t		*vlan_header = s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].vlan_header;
	pppoe_header_t 		*pppoe_header = s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].pppoe_header;
	ppp_payload_t 		*ppp_payload = s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].ppp_payload;
	ppp_header_t 		*ppp_hdr = s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].ppp_hdr;
	ppp_options_t 		*ppp_options = s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].ppp_options;

	ppp_hdr->code = CONFIG_ACK;
	
	rte_ether_addr_copy(&vrg_ccb.hsi_wan_src_mac, &eth_hdr->src_addr);
	rte_ether_addr_copy(&s_ppp_ccb->PPP_dst_mac, &eth_hdr->dst_addr);

	*mulen = ntohs(pppoe_header->length) + sizeof(struct rte_ether_hdr) + sizeof(pppoe_header_t) + sizeof(vlan_header_t);

	memset(buffer,0,MSG_BUF);
	rte_memcpy(buffer,eth_hdr,sizeof(struct rte_ether_hdr));
	rte_memcpy(buffer+14,vlan_header,sizeof(vlan_header_t));
 	rte_memcpy(buffer+14+sizeof(vlan_header_t),pppoe_header,sizeof(pppoe_header_t));
 	rte_memcpy(buffer+14+sizeof(vlan_header_t)+sizeof(pppoe_header_t),ppp_payload,sizeof(ppp_payload_t));
 	rte_memcpy(buffer+14+sizeof(vlan_header_t)+sizeof(pppoe_header_t)+sizeof(ppp_payload_t),ppp_hdr,sizeof(ppp_header_t));
 	rte_memcpy(buffer+14+sizeof(vlan_header_t)+sizeof(pppoe_header_t)+sizeof(ppp_payload_t)+sizeof(ppp_header_t),ppp_options,rte_cpu_to_be_16(ppp_hdr->length) - sizeof(ppp_header_t));

	RTE_LOG(INFO,EAL,"User %" PRIu16 " config ack built.\n", s_ppp_ccb->user_num);
	#ifdef _DP_DBG
 	puts("config ack built.");
	#endif
 	return TRUE;
}

/**
 * build_config_nak_rej
 *
 * purpose: For build PPP configure nak or reject, either in NCP or LCP phase.
 * input: 	*buffer - packet buffer,
 * 		    *s_ppp_ccb,
 * 			*mulen - packet length
 * output: 	TRUE/FALSE
 * return: 	packet buffer
 */
STATUS build_config_nak_rej(unsigned char* buffer, PPP_INFO_t *s_ppp_ccb, U16 *mulen)
{
	struct rte_ether_hdr *eth_hdr = s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].eth_hdr;
	vlan_header_t		*vlan_header = s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].vlan_header;
	pppoe_header_t 		*pppoe_header = s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].pppoe_header;
	ppp_payload_t 		*ppp_payload = s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].ppp_payload;
	ppp_header_t 		*ppp_hdr = s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].ppp_hdr;
	ppp_options_t 		*ppp_options = s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].ppp_options;

	rte_ether_addr_copy(&vrg_ccb.hsi_wan_src_mac, &eth_hdr->src_addr);
	rte_ether_addr_copy(&s_ppp_ccb->PPP_dst_mac, &eth_hdr->dst_addr);

	*mulen = ntohs(pppoe_header->length) + sizeof(struct rte_ether_hdr) + sizeof(pppoe_header_t) + sizeof(vlan_header_t);

	memset(buffer,0,MSG_BUF);
	rte_memcpy(buffer,eth_hdr,sizeof(struct rte_ether_hdr));
	rte_memcpy(buffer+14,vlan_header,sizeof(vlan_header_t));
 	rte_memcpy(buffer+14+sizeof(vlan_header_t),pppoe_header,sizeof(pppoe_header_t));
 	rte_memcpy(buffer+14+sizeof(vlan_header_t)+sizeof(pppoe_header_t),ppp_payload,sizeof(ppp_payload_t));
 	rte_memcpy(buffer+14+sizeof(vlan_header_t)+sizeof(pppoe_header_t)+sizeof(ppp_payload_t),ppp_hdr,sizeof(ppp_header_t));
 	rte_memcpy(buffer+14+sizeof(vlan_header_t)+sizeof(pppoe_header_t)+sizeof(ppp_payload_t)+sizeof(ppp_header_t),ppp_options,ntohs(ppp_hdr->length) - sizeof(ppp_header_t));

	RTE_LOG(INFO,EAL,"User %" PRIu16 " config nak/rej built.\n", s_ppp_ccb->user_num);
	#ifdef _DP_DBG
 	puts("config nak/rej built.");
	#endif 
 	return TRUE;
}

/**
 * build_echo_reply
 *
 * purpose: For build PPP echo reply, only in LCP phase.
 * input: 	*buffer - packet buffer,
 * 		    *s_ppp_ccb,
 * 			*mulen - packet length
 * output: 	TRUE/FALSE
 * return: 	packet buffer
 */
STATUS build_echo_reply(unsigned char* buffer, PPP_INFO_t *s_ppp_ccb, U16 *mulen)
{
	struct rte_ether_hdr *eth_hdr = s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].eth_hdr;
	vlan_header_t		*vlan_header = s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].vlan_header;
	pppoe_header_t 		*pppoe_header = s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].pppoe_header;
	ppp_payload_t 		*ppp_payload = s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].ppp_payload;
	ppp_header_t 		*ppp_hdr = s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].ppp_hdr;

	ppp_hdr->code = ECHO_REPLY;

	rte_ether_addr_copy(&vrg_ccb.hsi_wan_src_mac, &eth_hdr->src_addr);
	rte_ether_addr_copy(&s_ppp_ccb->PPP_dst_mac, &eth_hdr->dst_addr);

	pppoe_header->length = rte_cpu_to_be_16(sizeof(ppp_payload_t) + sizeof(ppp_header_t) + 4);
	*mulen = ntohs(pppoe_header->length) + sizeof(struct rte_ether_hdr) + sizeof(pppoe_header_t) + sizeof(vlan_header_t);

	memset(buffer,0,MSG_BUF);
	rte_memcpy(buffer,eth_hdr,sizeof(struct rte_ether_hdr));
	rte_memcpy(buffer+14,vlan_header,sizeof(vlan_header_t));
 	rte_memcpy(buffer+14+sizeof(vlan_header_t),pppoe_header,sizeof(pppoe_header_t));
 	rte_memcpy(buffer+14+sizeof(vlan_header_t)+sizeof(pppoe_header_t),ppp_payload,sizeof(ppp_payload_t));
 	rte_memcpy(buffer+14+sizeof(vlan_header_t)+sizeof(pppoe_header_t)+sizeof(ppp_payload_t),ppp_hdr,sizeof(ppp_header_t));
 	rte_memcpy(buffer+14+sizeof(vlan_header_t)+sizeof(pppoe_header_t)+sizeof(ppp_payload_t)+sizeof(ppp_header_t),&(s_ppp_ccb->magic_num),4);
 	
 	return TRUE;
}

/**
 * build_terminate_ack
 *
 * purpose: For build PPP terminate ack, either in NCP or LCP phase.
 * input: 	*buffer - packet buffer,
 * 		    *s_ppp_ccb,
 * 			*mulen - packet length
 * output: 	TRUE/FALSE
 * return: 	packet buffer
 */
STATUS build_terminate_ack(unsigned char* buffer, PPP_INFO_t *s_ppp_ccb, U16 *mulen)
{
	struct rte_ether_hdr *eth_hdr = s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].eth_hdr;
	vlan_header_t		*vlan_header = s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].vlan_header;
	pppoe_header_t 		*pppoe_header = s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].pppoe_header;
	ppp_payload_t 		*ppp_payload = s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].ppp_payload;
	ppp_header_t 		*ppp_hdr = s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].ppp_hdr;

	ppp_hdr->code = TERMIN_ACK;

	rte_ether_addr_copy(&vrg_ccb.hsi_wan_src_mac, &eth_hdr->src_addr);
	rte_ether_addr_copy(&s_ppp_ccb->PPP_dst_mac, &eth_hdr->dst_addr);

	*mulen = ntohs(pppoe_header->length) + sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t) + sizeof(pppoe_header_t);

	memset(buffer,0,MSG_BUF);
	rte_memcpy(buffer,eth_hdr,sizeof(struct rte_ether_hdr));
	rte_memcpy(buffer+14,vlan_header,sizeof(vlan_header_t));
 	rte_memcpy(buffer+14+sizeof(vlan_header_t),pppoe_header,sizeof(pppoe_header_t));
 	rte_memcpy(buffer+14+sizeof(vlan_header_t)+sizeof(pppoe_header_t),ppp_payload,sizeof(ppp_payload_t));
 	rte_memcpy(buffer+14+sizeof(vlan_header_t)+sizeof(pppoe_header_t)+sizeof(ppp_payload_t),ppp_hdr,sizeof(ppp_header_t));
 	
	RTE_LOG(INFO,EAL,"User %" PRIu16 " terminate ack built.\n", s_ppp_ccb->user_num);
	#ifdef _DP_DBG
 	puts("terminate ack built.");
	#endif
 	return TRUE;
}

/**
 * build_terminate_request
 *
 * purpose: For build PPP terminate request, either in NCP or LCP phase.
 * input: 	*buffer - packet buffer,
 * 		    *s_ppp_ccb,
 * 			*mulen - packet length
 * output: 	TRUE/FALSE
 * return: 	packet buffer
 */
STATUS build_terminate_request(unsigned char* buffer, PPP_INFO_t *s_ppp_ccb, U16 *mulen)
{
	struct rte_ether_hdr 	*eth_hdr = s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].eth_hdr;
	vlan_header_t		*vlan_header = s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].vlan_header;
	pppoe_header_t 		*pppoe_header = s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].pppoe_header;
	ppp_payload_t 		*ppp_payload = s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].ppp_payload;
	ppp_header_t 		*ppp_hdr = s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].ppp_hdr;

	rte_ether_addr_copy(&vrg_ccb.hsi_wan_src_mac, &eth_hdr->src_addr);
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
 	memset(buffer,0,MSG_BUF);
 	rte_memcpy(buffer,eth_hdr,sizeof(struct rte_ether_hdr));
	rte_memcpy(buffer+sizeof(struct rte_ether_hdr),vlan_header,sizeof(vlan_header_t));
 	rte_memcpy(buffer+sizeof(struct rte_ether_hdr)+sizeof(vlan_header_t),pppoe_header,sizeof(pppoe_header_t));
 	rte_memcpy(buffer+sizeof(struct rte_ether_hdr)+sizeof(vlan_header_t)+sizeof(pppoe_header_t),ppp_payload,sizeof(ppp_payload_t));
 	rte_memcpy(buffer+sizeof(struct rte_ether_hdr)+sizeof(vlan_header_t)+sizeof(pppoe_header_t)+sizeof(ppp_payload_t),ppp_hdr,sizeof(ppp_header_t));
 	
	RTE_LOG(INFO,EAL,"User %" PRIu16 " terminate request built.\n", s_ppp_ccb->user_num);
	#ifdef _DP_DBG
	puts("build terminate request.");
	#endif
 	return TRUE;
}

STATUS build_code_reject(__attribute__((unused)) unsigned char* buffer, __attribute__((unused)) PPP_INFO_t *s_ppp_ccb, __attribute__((unused)) U16 *mulen)
{
	puts("build code reject.");

	return TRUE;
}

/**
 * build_auth_request_pap
 *
 * purpose: For PAP auth, send after LCP nego complete.
 * input: 	*buffer - packet buffer,
 * 		    *s_ppp_ccb,
 * 			*mulen - packet length
 * output: 	TRUE/FALSE
 * return: 	packet buffer
 */
STATUS build_auth_request_pap(unsigned char* buffer, PPP_INFO_t *s_ppp_ccb, U16 *mulen)
{
	ppp_header_t 		ppp_pap_header;
	U8 			peer_id_length = strlen((const char *)(s_ppp_ccb->ppp_user_id));
	U8 			peer_passwd_length = strlen((const char *)(s_ppp_ccb->ppp_passwd));
	struct rte_ether_hdr 	*eth_hdr = s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].eth_hdr;
	vlan_header_t		*vlan_header = s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].vlan_header;
	pppoe_header_t 		*pppoe_header = s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].pppoe_header;
	ppp_payload_t 		*ppp_payload = s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].ppp_payload;
	ppp_header_t 		*ppp_hdr = s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].ppp_hdr;

	s_ppp_ccb->phase = AUTH_PHASE;

	rte_ether_addr_copy(&vrg_ccb.hsi_wan_src_mac, &eth_hdr->src_addr);
	rte_ether_addr_copy(&s_ppp_ccb->PPP_dst_mac, &eth_hdr->dst_addr);

	ppp_payload->ppp_protocol = rte_cpu_to_be_16(PAP_PROTOCOL);
	ppp_pap_header.code = PAP_REQUEST;
	ppp_pap_header.identifier = ppp_hdr->identifier;

	ppp_pap_header.length = 2 * sizeof(U8) + peer_id_length + peer_passwd_length + sizeof(ppp_header_t);
	pppoe_header->length = ppp_pap_header.length + sizeof(ppp_payload_t);
	ppp_pap_header.length = rte_cpu_to_be_16(ppp_pap_header.length);
	pppoe_header->length = rte_cpu_to_be_16(pppoe_header->length);

	*mulen = ntohs(pppoe_header->length) + sizeof(struct rte_ether_hdr) + sizeof(pppoe_header_t) + sizeof(vlan_header_t);

	memset(buffer,0,MSG_BUF);
	rte_memcpy(buffer,eth_hdr,sizeof(struct rte_ether_hdr));
 	rte_memcpy(buffer+sizeof(struct rte_ether_hdr),vlan_header,sizeof(vlan_header_t));
	rte_memcpy(buffer+sizeof(struct rte_ether_hdr)+sizeof(vlan_header_t),pppoe_header,sizeof(pppoe_header_t));
 	rte_memcpy(buffer+sizeof(struct rte_ether_hdr)+sizeof(vlan_header_t)+sizeof(pppoe_header_t),ppp_payload,sizeof(ppp_payload_t));
 	rte_memcpy(buffer+sizeof(struct rte_ether_hdr)+sizeof(vlan_header_t)+sizeof(pppoe_header_t)+sizeof(ppp_payload_t),&ppp_pap_header,sizeof(ppp_header_t));
 	rte_memcpy(buffer+sizeof(struct rte_ether_hdr)+sizeof(vlan_header_t)+sizeof(pppoe_header_t)+sizeof(ppp_payload_t)+sizeof(ppp_header_t),&peer_id_length,sizeof(U8));
 	rte_memcpy(buffer+sizeof(struct rte_ether_hdr)+sizeof(vlan_header_t)+sizeof(pppoe_header_t)+sizeof(ppp_payload_t)+sizeof(ppp_header_t)+sizeof(U8),s_ppp_ccb->ppp_user_id,peer_id_length);
 	rte_memcpy(buffer+sizeof(struct rte_ether_hdr)+sizeof(vlan_header_t)+sizeof(pppoe_header_t)+sizeof(ppp_payload_t)+sizeof(ppp_header_t)+sizeof(U8)+peer_id_length,&peer_passwd_length,sizeof(U8));
 	rte_memcpy(buffer+sizeof(struct rte_ether_hdr)+sizeof(vlan_header_t)+sizeof(pppoe_header_t)+sizeof(ppp_payload_t)+sizeof(ppp_header_t)+sizeof(U8)+peer_id_length+sizeof(U8),s_ppp_ccb->ppp_passwd,peer_passwd_length);
 	
	RTE_LOG(INFO,EAL,"User %" PRIu16 " pap request built.\n", s_ppp_ccb->user_num);
	#ifdef _DP_DBG
 	puts("pap request built.");
	#endif 
 	return TRUE;
}

/**
 * build_auth_ack_pap
 *
 * purpose: For Spirent test center, in pap, we will receive pap request packet.
 * input: 	*buffer - packet buffer,
 * 		    *s_ppp_ccb,
 * 			*mulen - packet length
 * output: 	TRUE/FALSE
 * return: 	packet buffer
 */
STATUS build_auth_ack_pap(unsigned char *buffer, PPP_INFO_t *s_ppp_ccb, U16 *mulen)
{
	ppp_header_t 		ppp_pap_header;
	const char 			*login_msg = "Login ok";
	ppp_pap_ack_nak_t 	ppp_pap_ack_nak;
	struct rte_ether_addr tmp_mac;
	struct rte_ether_hdr *eth_hdr = s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].eth_hdr;
	vlan_header_t		*vlan_header = s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].vlan_header;
	pppoe_header_t 		*pppoe_header = s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].pppoe_header;
	ppp_payload_t 		*ppp_payload = s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].ppp_payload;
	ppp_header_t 		*ppp_hdr = s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].ppp_hdr;

	rte_ether_addr_copy(&eth_hdr->src_addr, &tmp_mac);
	rte_ether_addr_copy(&eth_hdr->dst_addr, &eth_hdr->src_addr);
	rte_ether_addr_copy(&tmp_mac, &eth_hdr->dst_addr);

	ppp_payload->ppp_protocol = rte_cpu_to_be_16(PAP_PROTOCOL);
	ppp_pap_header.code = PAP_ACK;
	ppp_pap_header.identifier = ppp_hdr->identifier;

	ppp_pap_ack_nak.msg_length = strlen(login_msg);
	ppp_pap_ack_nak.msg = (U8 *)login_msg;

	ppp_pap_header.length = sizeof(ppp_header_t) + ppp_pap_ack_nak.msg_length + sizeof(ppp_pap_ack_nak.msg_length);
	pppoe_header->length = ppp_pap_header.length + sizeof(ppp_payload_t);
	ppp_pap_header.length = rte_cpu_to_be_16(ppp_pap_header.length);
	pppoe_header->length = rte_cpu_to_be_16(pppoe_header->length);

	*mulen = ntohs(pppoe_header->length) + sizeof(struct rte_ether_hdr) + sizeof(pppoe_header_t) + sizeof(vlan_header_t);

	memset(buffer,0,MSG_BUF);
	rte_memcpy(buffer,eth_hdr,sizeof(struct rte_ether_hdr));
 	rte_memcpy(buffer+14,vlan_header,sizeof(vlan_header_t));
	rte_memcpy(buffer+14+sizeof(vlan_header_t),pppoe_header,sizeof(pppoe_header_t));
 	rte_memcpy(buffer+14+sizeof(vlan_header_t)+sizeof(pppoe_header_t),ppp_payload,sizeof(ppp_payload_t));
 	rte_memcpy(buffer+14+sizeof(vlan_header_t)+sizeof(pppoe_header_t)+sizeof(ppp_payload_t),&ppp_pap_header,sizeof(ppp_header_t));
 	rte_memcpy(buffer+14+sizeof(vlan_header_t)+sizeof(pppoe_header_t)+sizeof(ppp_payload_t)+sizeof(ppp_header_t),&ppp_pap_ack_nak,sizeof(ppp_pap_ack_nak.msg_length)+ppp_pap_ack_nak.msg_length);
 	
	RTE_LOG(INFO,EAL,"User %" PRIu16 " pap ack built.\n", s_ppp_ccb->user_num);
	#ifdef _DP_DBG
 	puts("pap ack built.");
	#endif
 	return TRUE;
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

	RTE_LOG(INFO,EAL,"User %" PRIu16 " chap response built.\n", s_ppp_ccb->user_num);
	#ifdef _DP_DBG
 	puts("chap response built.");
	#endif 
 	return TRUE;
}
