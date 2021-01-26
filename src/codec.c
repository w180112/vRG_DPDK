#include "codec.h"
#include "dbg.h"
#include <rte_timer.h>
#include <rte_ether.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_log.h>
#include <rte_byteorder.h>
#include <cmdline_socket.h>

extern STATUS PPP_FSM(struct rte_timer *ppp, tPPP_PORT *port_ccb, U16 event);

extern struct rte_ring 		*rte_ring, *ds_mc_queue, *us_mc_queue, *rg_func_queue;
extern unsigned char 		*wan_mac;
extern struct cmdline 		*cl;
extern FILE					*fp;

/*============================ DECODE ===============================*/

/*****************************************************
 * ppp_decode_frame
 * 
 * input : pArg - mail.param
 * output: imsg, event
 * return: session ccb
 *****************************************************/
STATUS PPP_decode_frame(tPPP_MBX *mail, struct rte_ether_hdr *eth_hdr, vlan_header_t *vlan_header, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_header_t *ppp_lcp, ppp_options_t *ppp_options, uint16_t *event, struct rte_timer *tim, tPPP_PORT *port_ccb)
{
    uint16_t	mulen;

	if (mail->len > ETH_MTU){
	    DBG_PPP(DBGLVL1,0,"error! too large frame(%d)\n",mail->len);
	    return ERROR;
	}

	struct rte_ether_hdr *tmp_eth_hdr = (struct rte_ether_hdr *)mail->refp;
	vlan_header_t *tmp_vlan_header = (vlan_header_t *)(tmp_eth_hdr + 1);
	pppoe_header_t *tmp_pppoe_header = (pppoe_header_t *)(tmp_vlan_header + 1);
	rte_memcpy(eth_hdr,tmp_eth_hdr,sizeof(struct rte_ether_hdr));
	rte_memcpy(vlan_header,tmp_vlan_header,sizeof(vlan_header_t));
	rte_memcpy(pppoe_header,tmp_pppoe_header,sizeof(pppoe_header_t));

	/* we receive pppoe discovery packet and dont need to parse for ppp payload */
	#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	if (vlan_header->next_proto == rte_cpu_to_be_16(ETH_P_PPP_DIS)) {
	#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	if (vlan_header->next_proto == ETH_P_PPP_DIS) {
	#endif
		if (pppoe_header->code == PADS)
			port_ccb->phase = LCP_PHASE;
		return TRUE;
	}
	
	ppp_payload_t *tmp_ppp_payload = (ppp_payload_t *)(tmp_pppoe_header + 1);
	ppp_header_t *tmp_ppp_lcp = (ppp_header_t *)(tmp_ppp_payload + 1);

	rte_memcpy(ppp_payload,tmp_ppp_payload,sizeof(ppp_payload_t));
	rte_memcpy(ppp_lcp,tmp_ppp_lcp,sizeof(ppp_header_t));
	#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	rte_memcpy(ppp_options,tmp_ppp_lcp+1,rte_cpu_to_be_16(ppp_lcp->length)-4);
	#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	rte_memcpy(ppp_options,tmp_ppp_lcp+1,(ppp_lcp->length)-4);
	#endif
	mulen = mail->len;

    mulen -= 14; //DA-MAC[6] + SA-MAC[6] + ETH-TYPE[2]
    uint16_t total_lcp_length = ntohs(ppp_lcp->length);

    /* check the ppp is in LCP, AUTH or NCP phase */
	#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    if (ppp_payload->ppp_protocol == rte_cpu_to_be_16(IPCP_PROTOCOL)) {
	#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	if (ppp_payload->ppp_protocol == IPCP_PROTOCOL) {
	#endif
    	if (port_ccb->phase != IPCP_PHASE)
    		return FALSE;
    	if (decode_ipcp(pppoe_header,ppp_payload,ppp_lcp,ppp_options,total_lcp_length,event,tim,port_ccb) == FALSE){
    		return FALSE;
    	}
    }
	#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    else if (ppp_payload->ppp_protocol == rte_cpu_to_be_16(LCP_PROTOCOL)) {
	#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	else if (ppp_payload->ppp_protocol == LCP_PROTOCOL) {
	#endif
		switch(ppp_lcp->code) {
			case CONFIG_REQUEST : 
				if (port_ccb->phase != LCP_PHASE)
    				return FALSE;
				/* we check for if the request packet contains what we want */
				switch (check_nak_reject(CONFIG_NAK,pppoe_header,ppp_payload,ppp_lcp,ppp_options,total_lcp_length)) {
					case ERROR:
						return FALSE;
					case 1:
						*event = E_RECV_BAD_CONFIG_REQUEST;
						return TRUE;
					default:
						;
				}
				switch (check_nak_reject(CONFIG_REJECT,pppoe_header,ppp_payload,ppp_lcp,ppp_options,total_lcp_length)) {
					case ERROR:
						return FALSE;
					case 1:
						*event = E_RECV_BAD_CONFIG_REQUEST;
						return TRUE;
					default:
						;
				}
				*event = E_RECV_GOOD_CONFIG_REQUEST;
				#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
				ppp_lcp->length = rte_cpu_to_be_16(total_lcp_length);
				#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
				ppp_lcp->length = total_lcp_length;
				#endif
				return TRUE;
			case CONFIG_ACK :
				if (port_ccb->phase != LCP_PHASE)
    				return FALSE;
				if (ppp_lcp->identifier != port_ccb->identifier)
					return FALSE;
			
				/* only check magic number. Skip the bytes stored in ppp_options_t length to find magic num. */
				uint8_t ppp_options_length = 0;
				for(ppp_options_t *cur=ppp_options; ppp_options_length<=(rte_cpu_to_be_16(ppp_lcp->length)-4);) {
					if (cur->type == MAGIC_NUM) {
						for(int i=cur->length-3; i>=0; i--) {
							if (*(((uint8_t *)&(port_ccb->magic_num)) + i) != cur->val[i]) {
								RTE_LOG(INFO,EAL,"Session 0x%x recv ppp LCP magic number error.\n", rte_cpu_to_be_16(port_ccb->session_id));
								#ifdef _DP_DBG
								puts("recv ppp LCP magic number error");
								#endif
								return FALSE;
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
				return TRUE;
			case CONFIG_REJECT :
				*event = E_RECV_CONFIG_NAK_REJ;
				RTE_LOG(INFO,EAL,"Session 0x%x rrecv LCP reject message with option %x.\n", rte_cpu_to_be_16(port_ccb->session_id), ppp_options->type);
				#ifdef _DP_DBG
				printf("recv LCP reject message with option %x\n", ppp_options->type);
				#endif
				if (ppp_options->type == AUTH) {
					if (port_ccb->is_pap_auth == FALSE)
						return FALSE;
					port_ccb->is_pap_auth = FALSE;
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
				if (port_ccb->phase < LCP_PHASE)
    				return FALSE;
				*event = E_RECV_ECHO_REPLY_REQUEST_DISCARD_REQUEST;
				return TRUE;
			case ECHO_REPLY:
				if (port_ccb->phase < LCP_PHASE)
    				return FALSE;
				*event = E_RECV_ECHO_REPLY_REQUEST_DISCARD_REQUEST;
				return TRUE;
			default :
				*event = E_RECV_UNKNOWN_CODE;
		}
	}

	/* in AUTH phase, if the packet is not what we want, then send nak packet and just close process */
	else if (ppp_payload->ppp_protocol == rte_cpu_to_be_16(AUTH_PROTOCOL)) {
		if (port_ccb->phase != AUTH_PHASE)
			return FALSE;
		ppp_pap_ack_nak_t ppp_pap_ack_nak, *tmp_ppp_pap_ack_nak = (ppp_pap_ack_nak_t *)(tmp_ppp_lcp + 1);
		rte_memcpy(&ppp_pap_ack_nak,tmp_ppp_pap_ack_nak,tmp_ppp_pap_ack_nak->msg_length + sizeof(uint8_t));
		if (ppp_lcp->code == AUTH_ACK) {
			RTE_LOG(INFO,EAL,"Session 0x%x auth success.\n", rte_cpu_to_be_16(port_ccb->session_id));
			#ifdef _DP_DBG
			puts("auth success.");
			#endif
			port_ccb->phase = IPCP_PHASE;
			return TRUE;
		}
		else if (ppp_lcp->code == AUTH_NAK) {
    		port_ccb->phase = LCP_PHASE;
    		PPP_FSM(&(port_ccb->ppp),port_ccb,E_CLOSE);
			RTE_LOG(INFO,EAL,"Session 0x%x auth fail.\n", rte_cpu_to_be_16(port_ccb->session_id));
			#ifdef _DP_DBG
			puts("auth fail.");
			#endif
			return FALSE;
		}
		else if (ppp_lcp->code == AUTH_REQUEST) {
			unsigned char buffer[MSG_BUF];
    		uint16_t mulen;
    		tPPP_PORT tmp_port_ccb;

    		port_ccb->phase = AUTH_PHASE;
    		tmp_port_ccb.ppp_phase[0].eth_hdr = eth_hdr;
			tmp_port_ccb.ppp_phase[0].vlan_header = vlan_header;
    		tmp_port_ccb.ppp_phase[0].pppoe_header = pppoe_header;
    		tmp_port_ccb.ppp_phase[0].ppp_payload = ppp_payload;
    		tmp_port_ccb.ppp_phase[0].ppp_lcp = ppp_lcp;
    		tmp_port_ccb.ppp_phase[0].ppp_options = NULL;
    		tmp_port_ccb.cp = 0;
			tmp_port_ccb.session_id = port_ccb->session_id;
			if (build_auth_ack_pap(buffer,&tmp_port_ccb,&mulen) < 0)
				return FALSE;
				
			drv_xmit(buffer,mulen);
			RTE_LOG(INFO,EAL,"Session 0x%x recv pap request.\n", rte_cpu_to_be_16(port_ccb->session_id));
			#ifdef _DP_DBG
			puts("recv pap request");
			#endif
			return FALSE;
		}
	}
	else {
		RTE_LOG(INFO,EAL,"Session 0x%x recv unknown PPP protocol.\n", rte_cpu_to_be_16(port_ccb->session_id));
		#ifdef _DP_DBG
		puts("unknown PPP protocol");
		#endif
		return FALSE;
	}

	return TRUE;
}

/*******************************************************************
 * decode_ipcp
 * 
 * input : pppoe_header,ppp_payload,ppp_lcp,
 * 			ppp_options,total_lcp_length,event,tim,port_ccb
 * output: event
 * return: error
 *******************************************************************/
STATUS decode_ipcp(pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_header_t *ppp_lcp, ppp_options_t *ppp_options, uint16_t total_lcp_length, uint16_t *event, struct rte_timer *tim, tPPP_PORT *port_ccb)
{
	switch(ppp_lcp->code) {
		case CONFIG_REQUEST : 
			switch (check_ipcp_nak_rej(CONFIG_NAK,pppoe_header,ppp_payload,ppp_lcp,ppp_options,total_lcp_length)) {
				case ERROR:
					return FALSE;
				case 1:
					*event = E_RECV_BAD_CONFIG_REQUEST;
					return TRUE;
				default:
					;
			}
			switch (check_ipcp_nak_rej(CONFIG_REJECT,pppoe_header,ppp_payload,ppp_lcp,ppp_options,total_lcp_length)) {
				case ERROR:
					return FALSE;
				case 1:
					*event = E_RECV_BAD_CONFIG_REQUEST;
					return TRUE;
				default:
					;
			}
			rte_memcpy(&(port_ccb->ipv4_gw),ppp_options->val,sizeof(port_ccb->ipv4_gw));
			*event = E_RECV_GOOD_CONFIG_REQUEST;
			ppp_lcp->length = rte_cpu_to_be_16(total_lcp_length);
			return TRUE;
		case CONFIG_ACK :
			if (ppp_lcp->identifier != port_ccb->identifier)
				return FALSE;
			rte_timer_stop(tim);
			*event = E_RECV_CONFIG_ACK;
			rte_memcpy(&(port_ccb->ipv4),ppp_options->val,sizeof(port_ccb->ipv4));
			return TRUE;
		case CONFIG_NAK : 
			// if we receive nak packet, the option field contains correct ip address we want
			rte_memcpy(&(port_ccb->ipv4),ppp_options->val,4);
			*event = E_RECV_CONFIG_NAK_REJ;
			return TRUE;
		case CONFIG_REJECT :
			*event = E_RECV_CONFIG_NAK_REJ;
			return TRUE;
		case TERMIN_REQUEST :
			*event = E_RECV_TERMINATE_REQUEST;
			return TRUE;
		case TERMIN_ACK :
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
 * 		    *ppp_lcp, 
 * 		    *ppp_options, 
 * 		    total_lcp_length
 * output: 	TRUE/FALSE
 * return: 	should send NAK/REJ or ACK
 **/
STATUS check_ipcp_nak_rej(uint8_t flag, pppoe_header_t *pppoe_header, __attribute__((unused)) ppp_payload_t *ppp_payload, ppp_header_t *ppp_lcp, ppp_options_t *ppp_options, uint16_t total_lcp_length)
{
	ppp_options_t *tmp_buf = (ppp_options_t *)rte_malloc(NULL,MSG_BUF*sizeof(char),0);
	ppp_options_t *tmp_cur = tmp_buf;
	int bool_flag = 0;
	uint16_t tmp_total_length = 4;
	
	memset(tmp_buf,0,MSG_BUF);
	rte_memcpy(tmp_buf,ppp_options,MSG_BUF);

	ppp_lcp->length = sizeof(ppp_header_t);
	for (ppp_options_t *cur=ppp_options; tmp_total_length<total_lcp_length; cur=(ppp_options_t *)((char *)cur + cur->length)) {
		if (flag == CONFIG_NAK) {
			if (cur->type == IP_ADDRESS && cur->val[0] == 0) {
				bool_flag = 1;
				rte_memcpy(tmp_cur,cur,cur->length);
				ppp_lcp->length += cur->length;
				tmp_cur = (ppp_options_t *)((char *)tmp_cur + cur->length);
			}
		}
		else {
			if (cur->type != IP_ADDRESS) {
				bool_flag = 1;
				rte_memcpy(tmp_cur,cur,cur->length);
				ppp_lcp->length += cur->length;
				tmp_cur = (ppp_options_t *)((char *)tmp_cur + cur->length);
			}
		}
		tmp_total_length += cur->length;
	}

	if (bool_flag == 1) {
		rte_memcpy(ppp_options,tmp_buf,ppp_lcp->length - 4);
		pppoe_header->length = rte_cpu_to_be_16((ppp_lcp->length) + sizeof(ppp_payload_t));
		ppp_lcp->length = rte_cpu_to_be_16(ppp_lcp->length);
		ppp_lcp->code = flag;
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
 * 		    *ppp_lcp, 
 * 		    *ppp_options, 
 * 		    total_lcp_length
 * output: 	TRUE/FALSE
 * return: 	should send NAK/REJ or ACK
 **/
STATUS check_nak_reject(uint8_t flag, pppoe_header_t *pppoe_header, __attribute__((unused)) ppp_payload_t *ppp_payload, ppp_header_t *ppp_lcp, ppp_options_t *ppp_options, uint16_t total_lcp_length)
{
	ppp_options_t 	*tmp_buf = (ppp_options_t *)rte_malloc(NULL,MSG_BUF*sizeof(char),0);
	ppp_options_t 	*tmp_cur = tmp_buf;
	int 			bool_flag = 0;
	uint16_t 		tmp_total_length = 4;
	
	memset(tmp_buf,0,MSG_BUF);
	rte_memcpy(tmp_buf,ppp_options,MSG_BUF);

	ppp_lcp->length = sizeof(ppp_header_t);
	for(ppp_options_t *cur=ppp_options; tmp_total_length<total_lcp_length; cur=(ppp_options_t *)((char *)cur + cur->length)) {
		if (flag == CONFIG_NAK) {
			if (cur->type == MRU && (cur->val[0] != 0x5 || cur->val[1] != 0xD4)) {
				bool_flag = 1;
				cur->val[0] = 0x5;
				cur->val[1] = 0xD4;
				rte_memcpy(tmp_cur,cur,cur->length);
				ppp_lcp->length += cur->length;
				tmp_cur = (ppp_options_t *)((char *)tmp_cur + cur->length);
			}
		}
		else {
			if (cur->type != MAGIC_NUM && cur->type != MRU && cur->type != AUTH) {
				bool_flag= 1;
				rte_memcpy(tmp_cur,cur,cur->length);
				ppp_lcp->length += cur->length;
				tmp_cur = (ppp_options_t *)((char *)tmp_cur + cur->length);
			}
		}
		tmp_total_length += cur->length;
	}

	if (bool_flag== 1) {
		rte_memcpy(ppp_options,tmp_buf,ppp_lcp->length - 4);
		pppoe_header->length = rte_cpu_to_be_16((ppp_lcp->length) + sizeof(ppp_payload_t));
		ppp_lcp->length = rte_cpu_to_be_16(ppp_lcp->length);
		ppp_lcp->code = flag;
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
 * input: 	*port_ccb
 * 			*time - PPPoE timer
 * output: 	TRUE/FALSE
 */
STATUS build_padi(__attribute__((unused)) struct rte_timer *tim, tPPP_PORT *port_ccb)
{
	unsigned char 		buffer[MSG_BUF];
	uint16_t 			mulen;
	struct rte_ether_hdr 	eth_hdr;
	vlan_header_t		vlan_header;
	pppoe_header_t 		pppoe_header;
	pppoe_header_tag_t 	pppoe_header_tag;

	if (port_ccb->pppoe_phase.timer_counter >= port_ccb->pppoe_phase.max_retransmit) {
		RTE_LOG(INFO,EAL,"timeout when sending PADI\n");
		#ifdef _DP_DBG
		puts("timeout when sending PADI");
		#endif
		PPP_bye(port_ccb);
	}
	for(int i=0; i<6; i++) {
 		eth_hdr.s_addr.addr_bytes[i] = port_ccb->src_mac[i];
 		eth_hdr.d_addr.addr_bytes[i] = 0xff;
	}
	#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	eth_hdr.ether_type = rte_cpu_to_be_16(VLAN);
	#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	eth_hdr.ether_type = VLAN;
	#endif

	vlan_header.tci_union.tci_struct.priority = 0;
	vlan_header.tci_union.tci_struct.DEI = 0;
	vlan_header.tci_union.tci_struct.vlan_id = port_ccb->vlan;
	#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	vlan_header.next_proto = rte_cpu_to_be_16(ETH_P_PPP_DIS);
	vlan_header.tci_union.tci_value = rte_cpu_to_be_16(vlan_header.tci_union.tci_value);
	#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	vlan_header.next_proto = ETH_P_PPP_DIS;
	vlan_header.tci_union.tci_value = vlan_header.tci_union.tci_value;
	#endif

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
	port_ccb->pppoe_phase.timer_counter++;

	return TRUE;
}

/**
 * build_padr
 *
 * purpose: For build PPPoE request and send.
 * input: 	*port_ccb
 * 			*time - PPPoE timer
 * output: 	TRUE/FALSE
 */
STATUS build_padr(__attribute__((unused)) struct rte_timer *tim, tPPP_PORT *port_ccb)
{
	unsigned char 		buffer[MSG_BUF];
	uint16_t 			mulen;
	pppoe_header_tag_t 	*tmp_pppoe_header_tag = (pppoe_header_tag_t *)((pppoe_header_t *)((vlan_header_t *)((struct rte_ether_hdr *)buffer + 1) + 1) + 1);

	if (port_ccb->pppoe_phase.timer_counter >= port_ccb->pppoe_phase.max_retransmit) {
		RTE_LOG(INFO,EAL,"timeout when sending PADR\n");
		#ifdef _DP_DBG
		puts("timeout when sending PADR");
		#endif
		PPP_bye(port_ccb);
	}
	rte_memcpy(port_ccb->pppoe_phase.eth_hdr->s_addr.addr_bytes,port_ccb->src_mac,ETH_ALEN);
 	rte_memcpy(port_ccb->pppoe_phase.eth_hdr->d_addr.addr_bytes,port_ccb->dst_mac,ETH_ALEN);
 	port_ccb->pppoe_phase.pppoe_header->code = PADR;

 	uint32_t total_tag_length = 0;
	for(pppoe_header_tag_t *cur = tmp_pppoe_header_tag;;) {
		cur->type = port_ccb->pppoe_phase.pppoe_header_tag->type;
		cur->length = port_ccb->pppoe_phase.pppoe_header_tag->length;
		switch(ntohs(port_ccb->pppoe_phase.pppoe_header_tag->type)) {
			case END_OF_LIST:
				break;
			case SERVICE_NAME:
				break;
			case AC_NAME:
				/* We dont need to add ac-name tag to PADR. */
				port_ccb->pppoe_phase.pppoe_header_tag = (pppoe_header_tag_t *)((char *)(port_ccb->pppoe_phase.pppoe_header_tag) + 4 + ntohs(port_ccb->pppoe_phase.pppoe_header_tag->length));
				continue;
			case HOST_UNIQ:
			case AC_COOKIE:
			case RELAY_ID:
				if (cur->length != 0)
					rte_memcpy(cur->value,port_ccb->pppoe_phase.pppoe_header_tag->value,ntohs(cur->length));
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
		if (ntohs(port_ccb->pppoe_phase.pppoe_header_tag->type) == END_OF_LIST)
			break;

		/* to caculate total pppoe header tags' length, we need to add tag type and tag length field in each tag scanning. */
		total_tag_length = ntohs(cur->length) + 4 + total_tag_length;
		/* Fetch next tag field. */
		port_ccb->pppoe_phase.pppoe_header_tag = (pppoe_header_tag_t *)((char *)(port_ccb->pppoe_phase.pppoe_header_tag) + 4 + ntohs(port_ccb->pppoe_phase.pppoe_header_tag->length));
		cur = (pppoe_header_tag_t *)((char *)cur + 4 + ntohs(cur->length));
	}

	port_ccb->pppoe_phase.pppoe_header->length = rte_cpu_to_be_16(total_tag_length);
	mulen = sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t) + sizeof(pppoe_header_t) + total_tag_length;

	rte_memcpy(buffer,port_ccb->pppoe_phase.eth_hdr,sizeof(struct rte_ether_hdr));
	rte_memcpy(buffer+sizeof(struct rte_ether_hdr),port_ccb->pppoe_phase.vlan_header,sizeof(vlan_header_t));
	rte_memcpy(buffer+sizeof(struct rte_ether_hdr)+sizeof(vlan_header_t),port_ccb->pppoe_phase.pppoe_header,sizeof(pppoe_header_t));
	rte_memcpy(buffer+sizeof(struct rte_ether_hdr)+sizeof(vlan_header_t)+sizeof(pppoe_header_t),tmp_pppoe_header_tag,total_tag_length);
	drv_xmit(buffer,mulen);
	port_ccb->pppoe_phase.timer_counter++;

	return TRUE;
}

/**
 * build_padt
 *
 * purpose: For build PPPoE terminate and send.
 * input: 	*port_ccb
 * output: 	TRUE/FALSE
 */
STATUS build_padt(tPPP_PORT *port_ccb)
{
	unsigned char 		buffer[MSG_BUF];
	uint16_t 			mulen;
	struct rte_ether_hdr 	eth_hdr;
	vlan_header_t		vlan_header;
	pppoe_header_t 		pppoe_header;
	static uint16_t		total_user = MAX_USER;

	rte_memcpy(eth_hdr.s_addr.addr_bytes,port_ccb->src_mac,6);
 	rte_memcpy(eth_hdr.d_addr.addr_bytes,port_ccb->dst_mac,6);
 	#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	eth_hdr.ether_type = rte_cpu_to_be_16(VLAN);
	#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	eth_hdr.ether_type = VLAN;
	#endif

	vlan_header.tci_union.tci_struct.priority = 0;
	vlan_header.tci_union.tci_struct.DEI = 0;
	vlan_header.tci_union.tci_struct.vlan_id = port_ccb->vlan;
	#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	vlan_header.next_proto = rte_cpu_to_be_16(ETH_P_PPP_DIS);
	vlan_header.tci_union.tci_value = rte_cpu_to_be_16(vlan_header.tci_union.tci_value);
	#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	vlan_header.next_proto = ETH_P_PPP_DIS;
	vlan_header.tci_union.tci_value = vlan_header.tci_union.tci_value;
	#endif

	pppoe_header.ver_type = VER_TYPE;
	pppoe_header.code = PADT;
	pppoe_header.session_id = port_ccb->session_id; 
	pppoe_header.length = 0;

	mulen = sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t) + sizeof(pppoe_header_t);

	rte_memcpy(buffer,&eth_hdr,sizeof(struct rte_ether_hdr));
	rte_memcpy(buffer+sizeof(struct rte_ether_hdr),&vlan_header,sizeof(vlan_header_t));
	rte_memcpy(buffer+sizeof(struct rte_ether_hdr)+sizeof(vlan_header_t),&pppoe_header,sizeof(pppoe_header_t));
	drv_xmit(buffer,mulen);

	port_ccb->phase = END_PHASE;
	if (--total_user == 0) {
		printf("\n");
		rte_free(wan_mac);
    	rte_ring_free(rte_ring);
		rte_ring_free(ds_mc_queue);
		rte_ring_free(us_mc_queue);
		rte_ring_free(rg_func_queue);
    	fclose(fp);
		cmdline_stdin_exit(cl);
		exit(0);
	}
	return TRUE;
}

/**
 * build_config_request
 *
 * purpose: For build PPP configure request, either in NCP or LCP phase.
 * input: 	*buffer - packet buffer,
 * 		    *port_ccb,
 * 			*mulen - packet length
 * output: 	TRUE/FALSE
 * return: 	packet buffer
 */
STATUS build_config_request(unsigned char *buffer, tPPP_PORT *port_ccb, uint16_t *mulen)
{
	struct rte_ether_hdr 	*eth_hdr = port_ccb->ppp_phase[port_ccb->cp].eth_hdr;
	vlan_header_t		*vlan_header = port_ccb->ppp_phase[port_ccb->cp].vlan_header;
	pppoe_header_t 		*pppoe_header = port_ccb->ppp_phase[port_ccb->cp].pppoe_header;
	ppp_payload_t 		*ppp_payload = port_ccb->ppp_phase[port_ccb->cp].ppp_payload;
	ppp_header_t 		*ppp_lcp = port_ccb->ppp_phase[port_ccb->cp].ppp_lcp;
	ppp_options_t 		*ppp_options = port_ccb->ppp_phase[port_ccb->cp].ppp_options;

	srand(time(NULL));

	rte_memcpy(eth_hdr->s_addr.addr_bytes,port_ccb->src_mac,ETH_ALEN);
	rte_memcpy(eth_hdr->d_addr.addr_bytes,port_ccb->dst_mac,ETH_ALEN);
	#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	eth_hdr->ether_type = rte_cpu_to_be_16(VLAN);
	#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	eth_hdr->ether_type = VLAN;
	#endif

	vlan_header->tci_union.tci_struct.priority = 0;
	vlan_header->tci_union.tci_struct.DEI = 0;
	vlan_header->tci_union.tci_struct.vlan_id = port_ccb->vlan;
	#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	vlan_header->next_proto = rte_cpu_to_be_16(ETH_P_PPP_SES);
	vlan_header->tci_union.tci_value = rte_cpu_to_be_16(vlan_header->tci_union.tci_value);
	#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	vlan_header->next_proto = ETH_P_PPP_SES;
	vlan_header->tci_union.tci_value = vlan_header->tci_union.tci_value;
	#endif

	/* build ppp protocol and lcp header. */
 	pppoe_header->ver_type = VER_TYPE;
 	pppoe_header->code = 0;
 	/* We don't convert seesion id to little endian at first */
 	pppoe_header->session_id = port_ccb->session_id; 

 	ppp_lcp->code = CONFIG_REQUEST;
 	ppp_lcp->identifier = ((rand() % 254) + 1);

 	port_ccb->identifier = ppp_lcp->identifier;

 	pppoe_header->length = sizeof(ppp_header_t) + sizeof(ppp_payload->ppp_protocol);
 	ppp_lcp->length = sizeof(ppp_header_t);

 	if (port_ccb->cp == 1) {
 		ppp_payload->ppp_protocol = rte_cpu_to_be_16(IPCP_PROTOCOL);
 		ppp_options->type = IP_ADDRESS;
 		rte_memcpy(ppp_options->val,&(port_ccb->ipv4),4);
 		ppp_options->length = sizeof(port_ccb->ipv4) + sizeof(ppp_options_t);
 		pppoe_header->length += ppp_options->length;
 		ppp_lcp->length += ppp_options->length;
 	}
 	else if (port_ccb->cp == 0) {
 		ppp_payload->ppp_protocol = rte_cpu_to_be_16(LCP_PROTOCOL);
 		/* options, max recv units */
 		ppp_options_t *cur = ppp_options;

 		cur->type = MRU;
 		cur->length = 0x4;
 		uint16_t max_recv_unit = rte_cpu_to_be_16(MAX_RECV);
 		rte_memcpy(cur->val,&max_recv_unit,sizeof(uint16_t));
 		pppoe_header->length += 4;
 		ppp_lcp->length += 4;

 		cur = (ppp_options_t *)((char *)(cur + 1) + sizeof(max_recv_unit));
 		/* option, auth */
 		if (port_ccb->is_pap_auth == TRUE) {
 			cur->type = AUTH;
 			cur->length = 0x4;
 			uint16_t auth_pro = rte_cpu_to_be_16(AUTH_PROTOCOL);
 			rte_memcpy(cur->val,&auth_pro,sizeof(uint16_t));
 			pppoe_header->length += 4;
 			ppp_lcp->length += 4;

 			cur = (ppp_options_t *)((char *)(cur + 1) + sizeof(auth_pro));
 		}
 		/* options, magic number */
 		cur->type = MAGIC_NUM;
 		cur->length = 0x6;
 		port_ccb->magic_num = rte_cpu_to_be_32((rand() % 0xFFFFFFFE) + 1);
 		rte_memcpy(cur->val,&(port_ccb->magic_num),sizeof(uint32_t));
 		pppoe_header->length += 6;
 		ppp_lcp->length += 6;
	}

	*mulen = pppoe_header->length + sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t) + sizeof(pppoe_header_t);

 	pppoe_header->length = rte_cpu_to_be_16(pppoe_header->length);
 	ppp_lcp->length = rte_cpu_to_be_16(ppp_lcp->length);
 	memset(buffer,0,MSG_BUF);
 	rte_memcpy(buffer,eth_hdr,14);
	rte_memcpy(buffer+14,vlan_header,sizeof(vlan_header_t));
 	rte_memcpy(buffer+14+sizeof(vlan_header_t),pppoe_header,sizeof(pppoe_header_t));
 	rte_memcpy(buffer+14+sizeof(vlan_header_t)+sizeof(pppoe_header_t),ppp_payload,sizeof(ppp_payload_t));
 	rte_memcpy(buffer+14+sizeof(vlan_header_t)+sizeof(pppoe_header_t)+sizeof(ppp_payload_t),ppp_lcp,sizeof(ppp_header_t));
 	rte_memcpy(buffer+14+sizeof(vlan_header_t)+sizeof(pppoe_header_t)+sizeof(ppp_payload_t)+sizeof(ppp_header_t),ppp_options,rte_cpu_to_be_16(ppp_lcp->length) - sizeof(ppp_header_t));

	RTE_LOG(INFO,EAL,"Session 0x%x config request built.\n", rte_cpu_to_be_16(port_ccb->session_id));
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
 * 		    *port_ccb,
 * 			*mulen - packet length
 * output: 	TRUE/FALSE
 * return: 	packet buffer
 */
STATUS build_config_ack(unsigned char* buffer, tPPP_PORT *port_ccb, uint16_t *mulen)
{
	struct rte_ether_hdr 	*eth_hdr = port_ccb->ppp_phase[port_ccb->cp].eth_hdr;
	vlan_header_t		*vlan_header = port_ccb->ppp_phase[port_ccb->cp].vlan_header;
	pppoe_header_t 		*pppoe_header = port_ccb->ppp_phase[port_ccb->cp].pppoe_header;
	ppp_payload_t 		*ppp_payload = port_ccb->ppp_phase[port_ccb->cp].ppp_payload;
	ppp_header_t 		*ppp_lcp = port_ccb->ppp_phase[port_ccb->cp].ppp_lcp;
	ppp_options_t 		*ppp_options = port_ccb->ppp_phase[port_ccb->cp].ppp_options;

	ppp_lcp->code = CONFIG_ACK;

	rte_memcpy(eth_hdr->s_addr.addr_bytes,port_ccb->src_mac,ETH_ALEN);
	rte_memcpy(eth_hdr->d_addr.addr_bytes,port_ccb->dst_mac,ETH_ALEN);

	*mulen = ntohs(pppoe_header->length) + sizeof(struct rte_ether_hdr) + sizeof(pppoe_header_t) + sizeof(vlan_header_t);

	memset(buffer,0,MSG_BUF);
	rte_memcpy(buffer,eth_hdr,sizeof(struct rte_ether_hdr));
	rte_memcpy(buffer+14,vlan_header,sizeof(vlan_header_t));
 	rte_memcpy(buffer+14+sizeof(vlan_header_t),pppoe_header,sizeof(pppoe_header_t));
 	rte_memcpy(buffer+14+sizeof(vlan_header_t)+sizeof(pppoe_header_t),ppp_payload,sizeof(ppp_payload_t));
 	rte_memcpy(buffer+14+sizeof(vlan_header_t)+sizeof(pppoe_header_t)+sizeof(ppp_payload_t),ppp_lcp,sizeof(ppp_header_t));
 	rte_memcpy(buffer+14+sizeof(vlan_header_t)+sizeof(pppoe_header_t)+sizeof(ppp_payload_t)+sizeof(ppp_header_t),ppp_options,rte_cpu_to_be_16(ppp_lcp->length) - sizeof(ppp_header_t));

	RTE_LOG(INFO,EAL,"Session 0x%x config ack built.\n", rte_cpu_to_be_16(port_ccb->session_id));
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
 * 		    *port_ccb,
 * 			*mulen - packet length
 * output: 	TRUE/FALSE
 * return: 	packet buffer
 */
STATUS build_config_nak_rej(unsigned char* buffer, tPPP_PORT *port_ccb, uint16_t *mulen)
{
	struct rte_ether_hdr 	*eth_hdr = port_ccb->ppp_phase[port_ccb->cp].eth_hdr;
	vlan_header_t		*vlan_header = port_ccb->ppp_phase[port_ccb->cp].vlan_header;
	pppoe_header_t 		*pppoe_header = port_ccb->ppp_phase[port_ccb->cp].pppoe_header;
	ppp_payload_t 		*ppp_payload = port_ccb->ppp_phase[port_ccb->cp].ppp_payload;
	ppp_header_t 		*ppp_lcp = port_ccb->ppp_phase[port_ccb->cp].ppp_lcp;
	ppp_options_t 		*ppp_options = port_ccb->ppp_phase[port_ccb->cp].ppp_options;

	rte_memcpy(eth_hdr->s_addr.addr_bytes,port_ccb->src_mac,ETH_ALEN);
	rte_memcpy(eth_hdr->d_addr.addr_bytes,port_ccb->dst_mac,ETH_ALEN);

	*mulen = ntohs(pppoe_header->length) + sizeof(struct rte_ether_hdr) + sizeof(pppoe_header_t) + sizeof(vlan_header_t);

	memset(buffer,0,MSG_BUF);
	rte_memcpy(buffer,eth_hdr,sizeof(struct rte_ether_hdr));
	rte_memcpy(buffer+14,vlan_header,sizeof(vlan_header_t));
 	rte_memcpy(buffer+14+sizeof(vlan_header_t),pppoe_header,sizeof(pppoe_header_t));
 	rte_memcpy(buffer+14+sizeof(vlan_header_t)+sizeof(pppoe_header_t),ppp_payload,sizeof(ppp_payload_t));
 	rte_memcpy(buffer+14+sizeof(vlan_header_t)+sizeof(pppoe_header_t)+sizeof(ppp_payload_t),ppp_lcp,sizeof(ppp_header_t));
 	rte_memcpy(buffer+14+sizeof(vlan_header_t)+sizeof(pppoe_header_t)+sizeof(ppp_payload_t)+sizeof(ppp_header_t),ppp_options,ntohs(ppp_lcp->length) - sizeof(ppp_header_t));

	RTE_LOG(INFO,EAL,"Session 0x%x config nak/rej built.\n", rte_cpu_to_be_16(port_ccb->session_id));
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
 * 		    *port_ccb,
 * 			*mulen - packet length
 * output: 	TRUE/FALSE
 * return: 	packet buffer
 */
STATUS build_echo_reply(unsigned char* buffer, tPPP_PORT *port_ccb, uint16_t *mulen)
{
	struct rte_ether_hdr *eth_hdr = port_ccb->ppp_phase[port_ccb->cp].eth_hdr;
	vlan_header_t		*vlan_header = port_ccb->ppp_phase[port_ccb->cp].vlan_header;
	pppoe_header_t 		*pppoe_header = port_ccb->ppp_phase[port_ccb->cp].pppoe_header;
	ppp_payload_t 		*ppp_payload = port_ccb->ppp_phase[port_ccb->cp].ppp_payload;
	ppp_header_t 		*ppp_lcp = port_ccb->ppp_phase[port_ccb->cp].ppp_lcp;

	ppp_lcp->code = ECHO_REPLY;

	rte_memcpy(eth_hdr->s_addr.addr_bytes,port_ccb->src_mac,ETH_ALEN);
	rte_memcpy(eth_hdr->d_addr.addr_bytes,port_ccb->dst_mac,ETH_ALEN);

	pppoe_header->length = rte_cpu_to_be_16(sizeof(ppp_payload_t) + sizeof(ppp_header_t) + 4);
	*mulen = ntohs(pppoe_header->length) + sizeof(struct rte_ether_hdr) + sizeof(pppoe_header_t) + sizeof(vlan_header_t);

	memset(buffer,0,MSG_BUF);
	rte_memcpy(buffer,eth_hdr,sizeof(struct rte_ether_hdr));
	rte_memcpy(buffer+14,vlan_header,sizeof(vlan_header_t));
 	rte_memcpy(buffer+14+sizeof(vlan_header_t),pppoe_header,sizeof(pppoe_header_t));
 	rte_memcpy(buffer+14+sizeof(vlan_header_t)+sizeof(pppoe_header_t),ppp_payload,sizeof(ppp_payload_t));
 	rte_memcpy(buffer+14+sizeof(vlan_header_t)+sizeof(pppoe_header_t)+sizeof(ppp_payload_t),ppp_lcp,sizeof(ppp_header_t));
 	rte_memcpy(buffer+14+sizeof(vlan_header_t)+sizeof(pppoe_header_t)+sizeof(ppp_payload_t)+sizeof(ppp_header_t),&(port_ccb->magic_num),4);
 	
 	return TRUE;
}

/**
 * build_terminate_ack
 *
 * purpose: For build PPP terminate ack, either in NCP or LCP phase.
 * input: 	*buffer - packet buffer,
 * 		    *port_ccb,
 * 			*mulen - packet length
 * output: 	TRUE/FALSE
 * return: 	packet buffer
 */
STATUS build_terminate_ack(unsigned char* buffer, tPPP_PORT *port_ccb, uint16_t *mulen)
{
	struct rte_ether_hdr 	*eth_hdr = port_ccb->ppp_phase[port_ccb->cp].eth_hdr;
	vlan_header_t		*vlan_header = port_ccb->ppp_phase[port_ccb->cp].vlan_header;
	pppoe_header_t 		*pppoe_header = port_ccb->ppp_phase[port_ccb->cp].pppoe_header;
	ppp_payload_t 		*ppp_payload = port_ccb->ppp_phase[port_ccb->cp].ppp_payload;
	ppp_header_t 		*ppp_lcp = port_ccb->ppp_phase[port_ccb->cp].ppp_lcp;

	ppp_lcp->code = TERMIN_ACK;

	rte_memcpy(eth_hdr->s_addr.addr_bytes,port_ccb->src_mac,ETH_ALEN);
	rte_memcpy(eth_hdr->d_addr.addr_bytes,port_ccb->dst_mac,ETH_ALEN);

	*mulen = ntohs(pppoe_header->length) + sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t) + sizeof(pppoe_header_t);

	memset(buffer,0,MSG_BUF);
	rte_memcpy(buffer,eth_hdr,sizeof(struct rte_ether_hdr));
	rte_memcpy(buffer+14,vlan_header,sizeof(vlan_header_t));
 	rte_memcpy(buffer+14+sizeof(vlan_header_t),pppoe_header,sizeof(pppoe_header_t));
 	rte_memcpy(buffer+14+sizeof(vlan_header_t)+sizeof(pppoe_header_t),ppp_payload,sizeof(ppp_payload_t));
 	rte_memcpy(buffer+14+sizeof(vlan_header_t)+sizeof(pppoe_header_t)+sizeof(ppp_payload_t),ppp_lcp,sizeof(ppp_header_t));
 	
	RTE_LOG(INFO,EAL,"Session 0x%x terminate ack built.\n", rte_cpu_to_be_16(port_ccb->session_id));
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
 * 		    *port_ccb,
 * 			*mulen - packet length
 * output: 	TRUE/FALSE
 * return: 	packet buffer
 */
STATUS build_terminate_request(unsigned char* buffer, tPPP_PORT *port_ccb, uint16_t *mulen)
{
	struct rte_ether_hdr 	*eth_hdr = port_ccb->ppp_phase[port_ccb->cp].eth_hdr;
	vlan_header_t		*vlan_header = port_ccb->ppp_phase[port_ccb->cp].vlan_header;
	pppoe_header_t 		*pppoe_header = port_ccb->ppp_phase[port_ccb->cp].pppoe_header;
	ppp_payload_t 		*ppp_payload = port_ccb->ppp_phase[port_ccb->cp].ppp_payload;
	ppp_header_t 		*ppp_lcp = port_ccb->ppp_phase[port_ccb->cp].ppp_lcp;

	rte_memcpy(eth_hdr->s_addr.addr_bytes,port_ccb->src_mac,ETH_ALEN);
	rte_memcpy(eth_hdr->d_addr.addr_bytes,port_ccb->dst_mac,ETH_ALEN);
	#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	eth_hdr->ether_type = rte_cpu_to_be_16(VLAN);
	#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	eth_hdr->ether_type = VLAN;
	#endif

	vlan_header->tci_union.tci_struct.priority = 0;
	vlan_header->tci_union.tci_struct.DEI = 0;
	vlan_header->tci_union.tci_struct.vlan_id = port_ccb->vlan;
	#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	vlan_header->next_proto = rte_cpu_to_be_16(ETH_P_PPP_SES);
	vlan_header->tci_union.tci_value = rte_cpu_to_be_16(vlan_header->tci_union.tci_value);
	#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	vlan_header->next_proto = ETH_P_PPP_SES;
	vlan_header->tci_union.tci_value = vlan_header->tci_union.tci_value;
	#endif
	/* build ppp protocol and lcp/ipcp header. */

 	pppoe_header->ver_type = VER_TYPE;
 	pppoe_header->code = 0;
 	/* We don't convert seesion id to little endian at first */
 	pppoe_header->session_id = port_ccb->session_id;

 	if (port_ccb->cp == 0) 
 		ppp_payload->ppp_protocol = rte_cpu_to_be_16(LCP_PROTOCOL);
 	else if (port_ccb->cp == 1)
 		ppp_payload->ppp_protocol = rte_cpu_to_be_16(IPCP_PROTOCOL);

 	ppp_lcp->code = TERMIN_REQUEST;
 	ppp_lcp->identifier = ((rand() % 254) + 1);

 	pppoe_header->length = sizeof(ppp_header_t) + sizeof(ppp_payload->ppp_protocol);
 	ppp_lcp->length = sizeof(ppp_header_t); 	


	*mulen = pppoe_header->length + sizeof(struct rte_ether_hdr) + sizeof(pppoe_header_t) + sizeof(vlan_header_t);
 	pppoe_header->length = rte_cpu_to_be_16(pppoe_header->length);
 	ppp_lcp->length = rte_cpu_to_be_16(ppp_lcp->length);
 	memset(buffer,0,MSG_BUF);
 	rte_memcpy(buffer,eth_hdr,sizeof(struct rte_ether_hdr));
	rte_memcpy(buffer+sizeof(struct rte_ether_hdr),vlan_header,sizeof(vlan_header_t));
 	rte_memcpy(buffer+sizeof(struct rte_ether_hdr)+sizeof(vlan_header_t),pppoe_header,sizeof(pppoe_header_t));
 	rte_memcpy(buffer+sizeof(struct rte_ether_hdr)+sizeof(vlan_header_t)+sizeof(pppoe_header_t),ppp_payload,sizeof(ppp_payload_t));
 	rte_memcpy(buffer+sizeof(struct rte_ether_hdr)+sizeof(vlan_header_t)+sizeof(pppoe_header_t)+sizeof(ppp_payload_t),ppp_lcp,sizeof(ppp_header_t));
 	
	RTE_LOG(INFO,EAL,"Session 0x%x terminate request built.\n", rte_cpu_to_be_16(port_ccb->session_id));
	#ifdef _DP_DBG
	puts("build terminate request.");
	#endif
 	return TRUE;
}

STATUS build_code_reject(__attribute__((unused)) unsigned char* buffer, __attribute__((unused)) tPPP_PORT *port_ccb, __attribute__((unused)) uint16_t *mulen)
{
	puts("build code reject.");

	return TRUE;
}

/**
 * build_auth_request_pap
 *
 * purpose: For PAP auth, send after LCP nego complete.
 * input: 	*buffer - packet buffer,
 * 		    *port_ccb,
 * 			*mulen - packet length
 * output: 	TRUE/FALSE
 * return: 	packet buffer
 */
STATUS build_auth_request_pap(unsigned char* buffer, tPPP_PORT *port_ccb, uint16_t *mulen)
{
	ppp_header_t 		ppp_pap_header;
	uint8_t 			peer_id_length = strlen((const char *)(port_ccb->user_id));
	uint8_t 			peer_passwd_length = strlen((const char *)(port_ccb->passwd));
	struct rte_ether_hdr 	*eth_hdr = port_ccb->ppp_phase[port_ccb->cp].eth_hdr;
	vlan_header_t		*vlan_header = port_ccb->ppp_phase[port_ccb->cp].vlan_header;
	pppoe_header_t 		*pppoe_header = port_ccb->ppp_phase[port_ccb->cp].pppoe_header;
	ppp_payload_t 		*ppp_payload = port_ccb->ppp_phase[port_ccb->cp].ppp_payload;
	ppp_header_t 		*ppp_lcp = port_ccb->ppp_phase[port_ccb->cp].ppp_lcp;

	port_ccb->phase = AUTH_PHASE;

	rte_memcpy(eth_hdr->s_addr.addr_bytes,port_ccb->src_mac,ETH_ALEN);
	rte_memcpy(eth_hdr->d_addr.addr_bytes,port_ccb->dst_mac,ETH_ALEN);

	ppp_payload->ppp_protocol = rte_cpu_to_be_16(AUTH_PROTOCOL);
	ppp_pap_header.code = AUTH_REQUEST;
	ppp_pap_header.identifier = ppp_lcp->identifier;

	ppp_pap_header.length = 2 * sizeof(uint8_t) + peer_id_length + peer_passwd_length + sizeof(ppp_header_t);
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
 	rte_memcpy(buffer+sizeof(struct rte_ether_hdr)+sizeof(vlan_header_t)+sizeof(pppoe_header_t)+sizeof(ppp_payload_t)+sizeof(ppp_header_t),&peer_id_length,sizeof(uint8_t));
 	rte_memcpy(buffer+sizeof(struct rte_ether_hdr)+sizeof(vlan_header_t)+sizeof(pppoe_header_t)+sizeof(ppp_payload_t)+sizeof(ppp_header_t)+sizeof(uint8_t),port_ccb->user_id,peer_id_length);
 	rte_memcpy(buffer+sizeof(struct rte_ether_hdr)+sizeof(vlan_header_t)+sizeof(pppoe_header_t)+sizeof(ppp_payload_t)+sizeof(ppp_header_t)+sizeof(uint8_t)+peer_id_length,&peer_passwd_length,sizeof(uint8_t));
 	rte_memcpy(buffer+sizeof(struct rte_ether_hdr)+sizeof(vlan_header_t)+sizeof(pppoe_header_t)+sizeof(ppp_payload_t)+sizeof(ppp_header_t)+sizeof(uint8_t)+peer_id_length+sizeof(uint8_t),port_ccb->passwd,peer_passwd_length);
 	
	RTE_LOG(INFO,EAL,"Session 0x%x pap request built.\n", rte_cpu_to_be_16(port_ccb->session_id));
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
 * 		    *port_ccb,
 * 			*mulen - packet length
 * output: 	TRUE/FALSE
 * return: 	packet buffer
 */
STATUS build_auth_ack_pap(unsigned char *buffer, tPPP_PORT *port_ccb, uint16_t *mulen)
{
	ppp_header_t 		ppp_pap_header;
	const char 			*login_msg = "Login ok";
	ppp_pap_ack_nak_t 	ppp_pap_ack_nak;
	unsigned char 		tmp_mac[ETH_ALEN];
	struct rte_ether_hdr 	*eth_hdr = port_ccb->ppp_phase[port_ccb->cp].eth_hdr;
	vlan_header_t		*vlan_header = port_ccb->ppp_phase[port_ccb->cp].vlan_header;
	pppoe_header_t 		*pppoe_header = port_ccb->ppp_phase[port_ccb->cp].pppoe_header;
	ppp_payload_t 		*ppp_payload = port_ccb->ppp_phase[port_ccb->cp].ppp_payload;
	ppp_header_t 		*ppp_lcp = port_ccb->ppp_phase[port_ccb->cp].ppp_lcp;

	rte_memcpy(tmp_mac,eth_hdr->s_addr.addr_bytes,ETH_ALEN);
	rte_memcpy(eth_hdr->s_addr.addr_bytes,eth_hdr->d_addr.addr_bytes,ETH_ALEN);
	rte_memcpy(eth_hdr->d_addr.addr_bytes,tmp_mac,6);

	ppp_payload->ppp_protocol = rte_cpu_to_be_16(AUTH_PROTOCOL);
	ppp_pap_header.code = AUTH_ACK;
	ppp_pap_header.identifier = ppp_lcp->identifier;

	ppp_pap_ack_nak.msg_length = strlen(login_msg);
	ppp_pap_ack_nak.msg = (uint8_t *)login_msg;

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
 	
	RTE_LOG(INFO,EAL,"Session 0x%x pap ack built.\n", rte_cpu_to_be_16(port_ccb->session_id));
	#ifdef _DP_DBG
 	puts("pap ack built.");
	#endif
 	return TRUE;
}