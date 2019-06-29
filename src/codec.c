#include "codec.h"
#include "dbg.h"
#include <rte_timer.h>
#include <rte_memcpy.h>
#include <rte_log.h>

extern STATUS PPP_FSM(struct rte_timer *ppp, tPPP_PORT *port_ccb, U16 event);

/*============================ DECODE ===============================*/

/*****************************************************
 * ppp_decode_frame
 * 
 * input : pArg - mail.param
 * output: imsg, event
 * return: session ccb
 *****************************************************/
STATUS PPP_decode_frame(tPPP_MBX *mail, struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_lcp_header_t *ppp_lcp, ppp_lcp_options_t *ppp_lcp_options, uint16_t *event, struct rte_timer *tim, tPPP_PORT *port_ccb)
{
    uint16_t	mulen;

	if (mail->len > ETH_MTU){
	    DBG_PPP(DBGLVL1,0,"error! too large frame(%d)\n",mail->len);
	    return ERROR;
	}

	struct ethhdr *tmp_eth_hdr = (struct ethhdr *)mail->refp;
	pppoe_header_t *tmp_pppoe_header = (pppoe_header_t *)(tmp_eth_hdr + 1);
	rte_memcpy(eth_hdr,tmp_eth_hdr,sizeof(struct ethhdr));
	rte_memcpy(pppoe_header,tmp_pppoe_header,sizeof(pppoe_header_t));

	/* we receive pppoe discovery packet and dont need to parse for ppp payload */
	if (eth_hdr->h_proto == htons(ETH_P_PPP_DIS)) {
		if (pppoe_header->code == PADS)
			port_ccb->phase = LCP_PHASE;
		return TRUE;
	}
	
	ppp_payload_t *tmp_ppp_payload = (ppp_payload_t *)(tmp_pppoe_header + 1);
	ppp_lcp_header_t *tmp_ppp_lcp = (ppp_lcp_header_t *)(tmp_ppp_payload + 1);

	rte_memcpy(ppp_payload,tmp_ppp_payload,sizeof(ppp_payload_t));
	rte_memcpy(ppp_lcp,tmp_ppp_lcp,sizeof(ppp_lcp_header_t));
	rte_memcpy(ppp_lcp_options,tmp_ppp_lcp+1,htons(ppp_lcp->length)-4);
	
	mulen = mail->len;

    mulen -= 14; //DA-MAC[6] + SA-MAC[6] + ETH-TYPE[2]
    uint16_t total_lcp_length = ntohs(ppp_lcp->length);

    /* check the ppp is in LCP, AUTH or NCP phase */
    if (ppp_payload->ppp_protocol == htons(IPCP_PROTOCOL)) {
    	if (port_ccb->phase != IPCP_PHASE)
    		return FALSE;
    	if (decode_ipcp(eth_hdr,pppoe_header,ppp_payload,ppp_lcp,ppp_lcp_options,total_lcp_length,event,tim,port_ccb) == FALSE){
    		return FALSE;
    	}
    }
    else if (ppp_payload->ppp_protocol == htons(LCP_PROTOCOL)) {
		switch(ppp_lcp->code) {
			case CONFIG_REQUEST : 
				if (port_ccb->phase != LCP_PHASE)
    				return FALSE;
				/* we check for if the request packet contains what we want */
				switch (check_nak_reject(CONFIG_NAK,eth_hdr,pppoe_header,ppp_payload,ppp_lcp,ppp_lcp_options,total_lcp_length)) {
					case ERROR:
						return FALSE;
					case 1:
						*event = E_RECV_BAD_CONFIG_REQUEST;
						return TRUE;
					default:
						;
				}
				switch (check_nak_reject(CONFIG_REJECT,eth_hdr,pppoe_header,ppp_payload,ppp_lcp,ppp_lcp_options,total_lcp_length)) {
					case ERROR:
						return FALSE;
					case 1:
						*event = E_RECV_BAD_CONFIG_REQUEST;
						return TRUE;
					default:
						;
				}
				*event = E_RECV_GOOD_CONFIG_REQUEST;
				ppp_lcp->length = htons(total_lcp_length);
				return TRUE;
			case CONFIG_ACK :
				if (port_ccb->phase != LCP_PHASE)
    				return FALSE;
				if (ppp_lcp->identifier != port_ccb->identifier)
					return FALSE;
			
				/* only check magic number. Skip the bytes stored in ppp_lcp_options_t length to find magic num. */
				for(ppp_lcp_options_t *cur=ppp_lcp_options; cur->type!=0;) {
					if (cur->type == MAGIC_NUM) {
						for(int i=cur->length-3; i>0; i--) {
							if (*(((uint8_t *)&(port_ccb->magic_num)) + i) != cur->val[i]) {
								RTE_LOG(INFO,EAL,"Session 0x%x recv ppp LCP magic number error.\n", htons(port_ccb->session_id));
								#ifdef _DP_DBG
								puts("recv ppp LCP magic number error");
								#endif
								return FALSE;
							}
						}
					}
					cur = (ppp_lcp_options_t *)((char *)cur + cur->length);
				}
				*event = E_RECV_CONFIG_ACK;
				rte_timer_stop(tim);
				return TRUE;
			case CONFIG_NAK : 
				*event = E_RECV_CONFIG_NAK_REJ;
				return TRUE;
			case CONFIG_REJECT :
				*event = E_RECV_CONFIG_NAK_REJ;
				RTE_LOG(INFO,EAL,"Session 0x%x rrecv LCP reject message with option %x.\n", htons(port_ccb->session_id), ppp_lcp_options->type);
				#ifdef _DP_DBG
				printf("recv LCP reject message with option %x\n", ppp_lcp_options->type);
				#endif
				if (ppp_lcp_options->type == AUTH) {
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
	else if (ppp_payload->ppp_protocol == htons(AUTH_PROTOCOL)) {
		if (port_ccb->phase != AUTH_PHASE)
			return FALSE;
		ppp_pap_ack_nak_t ppp_pap_ack_nak, *tmp_ppp_pap_ack_nak = (ppp_pap_ack_nak_t *)(tmp_ppp_lcp + 1);
		rte_memcpy(&ppp_pap_ack_nak,tmp_ppp_pap_ack_nak,tmp_ppp_pap_ack_nak->msg_length + sizeof(uint8_t));
		if (ppp_lcp->code == AUTH_ACK) {
			RTE_LOG(INFO,EAL,"Session 0x%x auth success.\n", htons(port_ccb->session_id));
			#ifdef _DP_DBG
			puts("auth success.");
			#endif
			port_ccb->phase = IPCP_PHASE;
			return TRUE;
		}
		else if (ppp_lcp->code == AUTH_NAK) {
    		tPPP_PORT tmp_port_ccb;

    		tmp_port_ccb.ppp_phase[0].state = S_OPENED;
    		tmp_port_ccb.ppp_phase[0].eth_hdr = eth_hdr;
    		tmp_port_ccb.ppp_phase[0].pppoe_header = pppoe_header;
    		tmp_port_ccb.ppp_phase[0].ppp_payload = ppp_payload;
    		tmp_port_ccb.ppp_phase[0].ppp_lcp = ppp_lcp;
    		tmp_port_ccb.ppp_phase[0].ppp_lcp_options = NULL;
    		tmp_port_ccb.cp = 0;
    		tmp_port_ccb.ppp = port_ccb->ppp;
    		PPP_FSM(&(tmp_port_ccb.ppp),&tmp_port_ccb,E_CLOSE);
			RTE_LOG(INFO,EAL,"Session 0x%x auth fail.\n", htons(port_ccb->session_id));
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
    		tmp_port_ccb.ppp_phase[0].pppoe_header = pppoe_header;
    		tmp_port_ccb.ppp_phase[0].ppp_payload = ppp_payload;
    		tmp_port_ccb.ppp_phase[0].ppp_lcp = ppp_lcp;
    		tmp_port_ccb.ppp_phase[0].ppp_lcp_options = NULL;
    		tmp_port_ccb.cp = 0;
    		if (build_auth_ack_pap(buffer,&tmp_port_ccb,&mulen) < 0)
        		return FALSE;
			drv_xmit(buffer,mulen);
			RTE_LOG(INFO,EAL,"Session 0x%x recv pap request.\n", htons(port_ccb->session_id));
			#ifdef _DP_DBG
			puts("recv pap request");
			#endif
			return FALSE;
		}
	}
	else {
		RTE_LOG(INFO,EAL,"Session 0x%x recv unknown PPP protocol.\n", htons(port_ccb->session_id));
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
 * input : eth_hdr,pppoe_header,ppp_payload,ppp_lcp,
 * 			ppp_lcp_options,total_lcp_length,event,tim,port_ccb
 * output: event
 * return: error
 *******************************************************************/
STATUS decode_ipcp(struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_lcp_header_t *ppp_lcp, ppp_lcp_options_t *ppp_lcp_options, uint16_t total_lcp_length, uint16_t *event, struct rte_timer *tim, tPPP_PORT *port_ccb)
{
	switch(ppp_lcp->code) {
		case CONFIG_REQUEST : 
			switch (check_ipcp_nak_rej(CONFIG_NAK,eth_hdr,pppoe_header,ppp_payload,ppp_lcp,ppp_lcp_options,total_lcp_length)) {
				case ERROR:
					return FALSE;
				case 1:
					*event = E_RECV_BAD_CONFIG_REQUEST;
					return TRUE;
				default:
					;
			}
			switch (check_ipcp_nak_rej(CONFIG_REJECT,eth_hdr,pppoe_header,ppp_payload,ppp_lcp,ppp_lcp_options,total_lcp_length)) {
				case ERROR:
					return FALSE;
				case 1:
					*event = E_RECV_BAD_CONFIG_REQUEST;
					return TRUE;
				default:
					;
			}
			rte_memcpy(&(port_ccb->ipv4_gw),ppp_lcp_options->val,sizeof(port_ccb->ipv4_gw));
			*event = E_RECV_GOOD_CONFIG_REQUEST;
			ppp_lcp->length = htons(total_lcp_length);
			return TRUE;
		case CONFIG_ACK :
			if (ppp_lcp->identifier != port_ccb->identifier)
				return FALSE;
			rte_timer_stop(tim);
			*event = E_RECV_CONFIG_ACK;
			rte_memcpy(&(port_ccb->ipv4),ppp_lcp_options->val,sizeof(port_ccb->ipv4));
			return TRUE;
		case CONFIG_NAK : 
			// if we receive nak packet, the option field contains correct ip address we want
			rte_memcpy(&(port_ccb->ipv4),ppp_lcp_options->val,4);
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

/********************************************************************************************
 * check_ipcp_nak_rej
 *
 * purpose: check whether IPCP config request we received includes PPP options we dont want.
 * input: 	flag - check NAK/REJ
 * 		   	*eth_hdr
 * 		    *pppoe_header, 
 * 		    *ppp_payload, 
 * 		    *ppp_lcp, 
 * 		    *ppp_lcp_options, 
 * 		    total_lcp_length
 * output: 	TRUE/FALSE
 * return: 	should send NAK/REJ or ACK
 *******************************************************************************************/
STATUS check_ipcp_nak_rej(uint8_t flag, __attribute__((unused)) struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header, __attribute__((unused)) ppp_payload_t *ppp_payload, ppp_lcp_header_t *ppp_lcp, ppp_lcp_options_t *ppp_lcp_options, uint16_t total_lcp_length)
{
	ppp_lcp_options_t *tmp_buf = (ppp_lcp_options_t *)malloc(MSG_BUF*sizeof(char));
	ppp_lcp_options_t *tmp_cur = tmp_buf;
	int bool = 0;
	uint16_t tmp_total_length = 4;
	
	memset(tmp_buf,0,MSG_BUF);
	rte_memcpy(tmp_buf,ppp_lcp_options,MSG_BUF);

	ppp_lcp->length = sizeof(ppp_lcp_header_t);
	for (ppp_lcp_options_t *cur=ppp_lcp_options; tmp_total_length<total_lcp_length; cur=(ppp_lcp_options_t *)((char *)cur + cur->length)) {
		if (flag == CONFIG_NAK) {
			if (cur->type == IP_ADDRESS && cur->val[0] == 0) {
				bool = 1;
				rte_memcpy(tmp_cur,cur,cur->length);
				ppp_lcp->length += cur->length;
				tmp_cur = (ppp_lcp_options_t *)((char *)tmp_cur + cur->length);
			}
		}
		else {
			if (cur->type != IP_ADDRESS) {
				bool = 1;
				rte_memcpy(tmp_cur,cur,cur->length);
				ppp_lcp->length += cur->length;
				tmp_cur = (ppp_lcp_options_t *)((char *)tmp_cur + cur->length);
			}
		}
		tmp_total_length += cur->length;
	}

	if (bool == 1) {
		rte_memcpy(ppp_lcp_options,tmp_buf,ppp_lcp->length - 4);
		pppoe_header->length = htons((ppp_lcp->length) + sizeof(ppp_payload_t));
		ppp_lcp->length = htons(ppp_lcp->length);
		ppp_lcp->code = flag;
		free(tmp_buf);

		return 1;
	}
	free(tmp_buf);
	return 0;
}

STATUS check_nak_reject(uint8_t flag, __attribute__((unused)) struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header, __attribute__((unused)) ppp_payload_t *ppp_payload, ppp_lcp_header_t *ppp_lcp, ppp_lcp_options_t *ppp_lcp_options, uint16_t total_lcp_length)
{
	ppp_lcp_options_t *tmp_buf = (ppp_lcp_options_t *)malloc(MSG_BUF*sizeof(char));
	ppp_lcp_options_t *tmp_cur = tmp_buf;
	int 			  bool = 0;
	uint16_t 		  tmp_total_length = 4;
	
	memset(tmp_buf,0,MSG_BUF);
	rte_memcpy(tmp_buf,ppp_lcp_options,MSG_BUF);

	ppp_lcp->length = sizeof(ppp_lcp_header_t);
	for(ppp_lcp_options_t *cur=ppp_lcp_options; tmp_total_length<total_lcp_length; cur=(ppp_lcp_options_t *)((char *)cur + cur->length)) {
		if (flag == CONFIG_NAK) {
			if (cur->type == MRU && (cur->val[0] != 0x5 || cur->val[1] != 0xD4)) {
				bool = 1;
				cur->val[0] = 0x5;
				cur->val[1] = 0xD4;
				rte_memcpy(tmp_cur,cur,cur->length);
				ppp_lcp->length += cur->length;
				tmp_cur = (ppp_lcp_options_t *)((char *)tmp_cur + cur->length);
			}
		}
		else {
			if (cur->type != MAGIC_NUM && cur->type != MRU && cur->type != AUTH) {
				bool = 1;
				rte_memcpy(tmp_cur,cur,cur->length);
				ppp_lcp->length += cur->length;
				tmp_cur = (ppp_lcp_options_t *)((char *)tmp_cur + cur->length);
			}
		}
		tmp_total_length += cur->length;
	}

	if (bool == 1) {
		rte_memcpy(ppp_lcp_options,tmp_buf,ppp_lcp->length - 4);
		pppoe_header->length = htons((ppp_lcp->length) + sizeof(ppp_payload_t));
		ppp_lcp->length = htons(ppp_lcp->length);
		ppp_lcp->code = flag;
		free(tmp_buf);

		return 1;
	}
	free(tmp_buf);
	return 0;
}

STATUS build_padi(__attribute__((unused)) struct rte_timer *tim, tPPP_PORT *port_ccb)
{
	unsigned char 		buffer[MSG_BUF];
	uint16_t 			mulen;
	struct ethhdr 		eth_hdr;
	pppoe_header_t 		pppoe_header;
	pppoe_header_tag_t 	pppoe_header_tag;

	if (port_ccb->pppoe_phase.timer_counter >= port_ccb->pppoe_phase.max_retransmit) {
		RTE_LOG(INFO,EAL,"timeout when sending PADI\n");
		#ifdef _DP_DBG
		puts("timeout when sending PADI");
		#endif
		kill(getpid(),SIGTERM);
	}
	for(int i=0; i<6; i++) {
 		eth_hdr.h_source[i] = port_ccb->src_mac[i];
 		eth_hdr.h_dest[i] = 0xff;
	}
	eth_hdr.h_proto = htons(ETH_P_PPP_DIS);
	
	pppoe_header.ver_type = VER_TYPE;
	pppoe_header.code = PADI;
	pppoe_header.session_id = 0; 

	pppoe_header_tag.type = htons(SERVICE_NAME); //padi tag type (service name)
	pppoe_header_tag.length = 0;

	pppoe_header.length = htons(sizeof(pppoe_header_tag_t));

	mulen = sizeof(struct ethhdr) + sizeof(pppoe_header_t) + sizeof(pppoe_header_tag_t);

	rte_memcpy(buffer,&eth_hdr,sizeof(struct ethhdr));
	rte_memcpy(buffer+sizeof(struct ethhdr),&pppoe_header,sizeof(pppoe_header_t));
	rte_memcpy(buffer+sizeof(struct ethhdr)+sizeof(pppoe_header_t),&pppoe_header_tag,sizeof(pppoe_header_tag_t));
	drv_xmit(buffer,mulen);
	port_ccb->pppoe_phase.timer_counter++;

	return TRUE;
}

/* rebuild pppoe tag */
STATUS build_padr(__attribute__((unused)) struct rte_timer *tim, tPPP_PORT *port_ccb)
{
	unsigned char buffer[MSG_BUF];
	uint16_t mulen;
	pppoe_header_tag_t *tmp_pppoe_header_tag = (pppoe_header_tag_t *)((pppoe_header_t *)((struct ethhdr *)buffer + 1) + 1);

	if (port_ccb->pppoe_phase.timer_counter >= port_ccb->pppoe_phase.max_retransmit) {
		RTE_LOG(INFO,EAL,"timeout when sending PADR\n");
		#ifdef _DP_DBG
		puts("timeout when sending PADR");
		#endif
		kill(getpid(),SIGTERM);
	}
	rte_memcpy(port_ccb->pppoe_phase.eth_hdr->h_source,port_ccb->src_mac,6);
 	rte_memcpy(port_ccb->pppoe_phase.eth_hdr->h_dest,port_ccb->dst_mac,6);
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

	port_ccb->pppoe_phase.pppoe_header->length = htons(total_tag_length);
	mulen = sizeof(struct ethhdr) + sizeof(pppoe_header_t) + total_tag_length;

	rte_memcpy(buffer,port_ccb->pppoe_phase.eth_hdr,sizeof(struct ethhdr));
	rte_memcpy(buffer+sizeof(struct ethhdr),port_ccb->pppoe_phase.pppoe_header,sizeof(pppoe_header_t));
	rte_memcpy(buffer+sizeof(struct ethhdr)+sizeof(pppoe_header_t),tmp_pppoe_header_tag,total_tag_length);
	drv_xmit(buffer,mulen);
	port_ccb->pppoe_phase.timer_counter++;

	return TRUE;
}

STATUS build_padt(tPPP_PORT *port_ccb)
{
	unsigned char 	buffer[MSG_BUF];
	uint16_t 		mulen;
	struct ethhdr 	eth_hdr;
	pppoe_header_t 	pppoe_header;

	rte_memcpy(eth_hdr.h_source,port_ccb->src_mac,6);
 	rte_memcpy(eth_hdr.h_dest,port_ccb->dst_mac,6);
 	eth_hdr.h_proto = htons(ETH_P_PPP_DIS);

	pppoe_header.ver_type = VER_TYPE;
	pppoe_header.code = PADT;
	pppoe_header.session_id = port_ccb->session_id; 
	pppoe_header.length = 0;

	mulen = sizeof(struct ethhdr) + sizeof(pppoe_header_t);

	rte_memcpy(buffer,&eth_hdr,sizeof(struct ethhdr));
	rte_memcpy(buffer+sizeof(struct ethhdr),&pppoe_header,sizeof(pppoe_header_t));
	drv_xmit(buffer,mulen);

	return TRUE;
}

STATUS build_config_request(unsigned char *buffer, tPPP_PORT *port_ccb, uint16_t *mulen)
{
	struct ethhdr 			*eth_hdr = port_ccb->ppp_phase[port_ccb->cp].eth_hdr;
	pppoe_header_t 			*pppoe_header = port_ccb->ppp_phase[port_ccb->cp].pppoe_header;
	ppp_payload_t 			*ppp_payload = port_ccb->ppp_phase[port_ccb->cp].ppp_payload;
	ppp_lcp_header_t 		*ppp_lcp = port_ccb->ppp_phase[port_ccb->cp].ppp_lcp;
	ppp_lcp_options_t 		*ppp_lcp_options = port_ccb->ppp_phase[port_ccb->cp].ppp_lcp_options;

	srand(time(NULL));

	rte_memcpy(eth_hdr->h_source,port_ccb->src_mac,6);
	rte_memcpy(eth_hdr->h_dest,port_ccb->dst_mac,6);
	eth_hdr->h_proto = htons(ETH_P_PPP_SES);

	/* build ppp protocol and lcp header. */
 	pppoe_header->ver_type = VER_TYPE;
 	pppoe_header->code = 0;
 	/* We don't convert seesion id to little endian at first */
 	pppoe_header->session_id = port_ccb->session_id; 

 	ppp_lcp->code = CONFIG_REQUEST;
 	ppp_lcp->identifier = ((rand() % 254) + 1);

 	port_ccb->identifier = ppp_lcp->identifier;

 	pppoe_header->length = sizeof(ppp_lcp_header_t) + sizeof(ppp_payload->ppp_protocol);
 	ppp_lcp->length = sizeof(ppp_lcp_header_t);

 	if (port_ccb->cp == 1) {
 		ppp_payload->ppp_protocol = htons(IPCP_PROTOCOL);
 		ppp_lcp_options->type = IP_ADDRESS;
 		rte_memcpy(ppp_lcp_options->val,&(port_ccb->ipv4),4);
 		ppp_lcp_options->length = sizeof(port_ccb->ipv4) + sizeof(ppp_lcp_options_t);
 		pppoe_header->length += ppp_lcp_options->length;
 		ppp_lcp->length += ppp_lcp_options->length;
 	}
 	else if (port_ccb->cp == 0) {
 		ppp_payload->ppp_protocol = htons(LCP_PROTOCOL);
 		/* options, max recv units */
 		ppp_lcp_options_t *cur = ppp_lcp_options;

 		cur->type = MRU;
 		cur->length = 0x4;
 		uint16_t max_recv_unit = htons(MAX_RECV);
 		rte_memcpy(cur->val,&max_recv_unit,sizeof(uint16_t));
 		pppoe_header->length += 4;
 		ppp_lcp->length += 4;

 		cur = (ppp_lcp_options_t *)((char *)(cur + 1) + sizeof(max_recv_unit));
 		/* option, auth */
 		if (port_ccb->is_pap_auth == TRUE) {
 			cur->type = AUTH;
 			cur->length = 0x4;
 			uint16_t auth_pro = htons(AUTH_PROTOCOL);
 			rte_memcpy(cur->val,&auth_pro,sizeof(uint16_t));
 			pppoe_header->length += 4;
 			ppp_lcp->length += 4;

 			cur = (ppp_lcp_options_t *)((char *)(cur + 1) + sizeof(auth_pro));
 		}
 		/* options, magic number */
 		cur->type = MAGIC_NUM;
 		cur->length = 0x6;
 		port_ccb->magic_num = htonl((rand() % 0xFFFFFFFE) + 1);
 		rte_memcpy(cur->val,&(port_ccb->magic_num),sizeof(uint32_t));
 		pppoe_header->length += 6;
 		ppp_lcp->length += 6;
	}

	*mulen = pppoe_header->length + 14 + sizeof(pppoe_header_t);

 	pppoe_header->length = htons(pppoe_header->length);
 	ppp_lcp->length = htons(ppp_lcp->length);
 	memset(buffer,0,MSG_BUF);
 	rte_memcpy(buffer,eth_hdr,14);
 	rte_memcpy(buffer+14,pppoe_header,sizeof(pppoe_header_t));
 	rte_memcpy(buffer+14+sizeof(pppoe_header_t),ppp_payload,sizeof(ppp_payload_t));
 	rte_memcpy(buffer+14+sizeof(pppoe_header_t)+sizeof(ppp_payload_t),ppp_lcp,sizeof(ppp_lcp_header_t));
 	rte_memcpy(buffer+14+sizeof(pppoe_header_t)+sizeof(ppp_payload_t)+sizeof(ppp_lcp_header_t),ppp_lcp_options,htons(ppp_lcp->length) - sizeof(ppp_lcp_header_t));

	RTE_LOG(INFO,EAL,"Session 0x%x config request built.\n", htons(port_ccb->session_id));
	#ifdef _DP_DBG
 	puts("config request built.");
 	//PRINT_MESSAGE(buffer,*mulen);
	#endif
 	return TRUE;
}

STATUS build_config_ack(unsigned char* buffer, tPPP_PORT *port_ccb, uint16_t *mulen)
{
	struct ethhdr 			*eth_hdr = port_ccb->ppp_phase[port_ccb->cp].eth_hdr;
	pppoe_header_t 			*pppoe_header = port_ccb->ppp_phase[port_ccb->cp].pppoe_header;
	ppp_payload_t 			*ppp_payload = port_ccb->ppp_phase[port_ccb->cp].ppp_payload;
	ppp_lcp_header_t 		*ppp_lcp = port_ccb->ppp_phase[port_ccb->cp].ppp_lcp;
	ppp_lcp_options_t 		*ppp_lcp_options = port_ccb->ppp_phase[port_ccb->cp].ppp_lcp_options;

	ppp_lcp->code = CONFIG_ACK;

	rte_memcpy(eth_hdr->h_source,port_ccb->src_mac,6);
	rte_memcpy(eth_hdr->h_dest,port_ccb->dst_mac,6);

	*mulen = ntohs(pppoe_header->length) + 14 + sizeof(pppoe_header_t);

	memset(buffer,0,MSG_BUF);
	rte_memcpy(buffer,eth_hdr,14);
 	rte_memcpy(buffer+14,pppoe_header,sizeof(pppoe_header_t));
 	rte_memcpy(buffer+14+sizeof(pppoe_header_t),ppp_payload,sizeof(ppp_payload_t));
 	rte_memcpy(buffer+14+sizeof(pppoe_header_t)+sizeof(ppp_payload_t),ppp_lcp,sizeof(ppp_lcp_header_t));
 	rte_memcpy(buffer+14+sizeof(pppoe_header_t)+sizeof(ppp_payload_t)+sizeof(ppp_lcp_header_t),ppp_lcp_options,htons(ppp_lcp->length) - sizeof(ppp_lcp_header_t));

	RTE_LOG(INFO,EAL,"Session 0x%x config ack built.\n", htons(port_ccb->session_id));
	#ifdef _DP_DBG
 	puts("config ack built.");
	#endif
 	return TRUE;
}

STATUS build_config_nak_rej(unsigned char* buffer, tPPP_PORT *port_ccb, uint16_t *mulen)
{
	struct ethhdr 			*eth_hdr = port_ccb->ppp_phase[port_ccb->cp].eth_hdr;
	pppoe_header_t 			*pppoe_header = port_ccb->ppp_phase[port_ccb->cp].pppoe_header;
	ppp_payload_t 			*ppp_payload = port_ccb->ppp_phase[port_ccb->cp].ppp_payload;
	ppp_lcp_header_t 		*ppp_lcp = port_ccb->ppp_phase[port_ccb->cp].ppp_lcp;
	ppp_lcp_options_t 		*ppp_lcp_options = port_ccb->ppp_phase[port_ccb->cp].ppp_lcp_options;

	rte_memcpy(eth_hdr->h_source,port_ccb->src_mac,6);
	rte_memcpy(eth_hdr->h_dest,port_ccb->dst_mac,6);

	*mulen = ntohs(pppoe_header->length) + 14 + sizeof(pppoe_header_t);

	memset(buffer,0,MSG_BUF);
	rte_memcpy(buffer,eth_hdr,14);
 	rte_memcpy(buffer+14,pppoe_header,sizeof(pppoe_header_t));
 	rte_memcpy(buffer+14+sizeof(pppoe_header_t),ppp_payload,sizeof(ppp_payload_t));
 	rte_memcpy(buffer+14+sizeof(pppoe_header_t)+sizeof(ppp_payload_t),ppp_lcp,sizeof(ppp_lcp_header_t));
 	rte_memcpy(buffer+14+sizeof(pppoe_header_t)+sizeof(ppp_payload_t)+sizeof(ppp_lcp_header_t),ppp_lcp_options,ntohs(ppp_lcp->length) - sizeof(ppp_lcp_header_t));

	RTE_LOG(INFO,EAL,"Session 0x%x config nak/rej built.\n", htons(port_ccb->session_id));
	#ifdef _DP_DBG
 	puts("config nak/rej built.");
	#endif 
 	return TRUE;
}

STATUS build_echo_reply(unsigned char* buffer, tPPP_PORT *port_ccb, uint16_t *mulen)
{
	struct ethhdr 			*eth_hdr = port_ccb->ppp_phase[port_ccb->cp].eth_hdr;
	pppoe_header_t 			*pppoe_header = port_ccb->ppp_phase[port_ccb->cp].pppoe_header;
	ppp_payload_t 			*ppp_payload = port_ccb->ppp_phase[port_ccb->cp].ppp_payload;
	ppp_lcp_header_t 		*ppp_lcp = port_ccb->ppp_phase[port_ccb->cp].ppp_lcp;

	ppp_lcp->code = ECHO_REPLY;

	rte_memcpy(eth_hdr->h_source,port_ccb->src_mac,6);
	rte_memcpy(eth_hdr->h_dest,port_ccb->dst_mac,6);

	pppoe_header->length = htons(sizeof(ppp_payload_t) + sizeof(ppp_lcp_header_t) + 4);
	*mulen = ntohs(pppoe_header->length) + 14 + sizeof(pppoe_header_t);

	memset(buffer,0,MSG_BUF);
	rte_memcpy(buffer,eth_hdr,14);
 	rte_memcpy(buffer+14,pppoe_header,sizeof(pppoe_header_t));
 	rte_memcpy(buffer+14+sizeof(pppoe_header_t),ppp_payload,sizeof(ppp_payload_t));
 	rte_memcpy(buffer+14+sizeof(pppoe_header_t)+sizeof(ppp_payload_t),ppp_lcp,sizeof(ppp_lcp_header_t));
 	rte_memcpy(buffer+14+sizeof(pppoe_header_t)+sizeof(ppp_payload_t)+sizeof(ppp_lcp_header_t),&(port_ccb->magic_num),4);
 	
 	return TRUE;
}

STATUS build_terminate_ack(unsigned char* buffer, tPPP_PORT *port_ccb, uint16_t *mulen)
{
	struct ethhdr 			*eth_hdr = port_ccb->ppp_phase[port_ccb->cp].eth_hdr;
	pppoe_header_t 			*pppoe_header = port_ccb->ppp_phase[port_ccb->cp].pppoe_header;
	ppp_payload_t 			*ppp_payload = port_ccb->ppp_phase[port_ccb->cp].ppp_payload;
	ppp_lcp_header_t 		*ppp_lcp = port_ccb->ppp_phase[port_ccb->cp].ppp_lcp;

	ppp_lcp->code = TERMIN_ACK;

	rte_memcpy(eth_hdr->h_source,port_ccb->src_mac,6);
	rte_memcpy(eth_hdr->h_dest,port_ccb->dst_mac,6);

	*mulen = ntohs(pppoe_header->length) + 14 + sizeof(pppoe_header_t);

	memset(buffer,0,MSG_BUF);
	rte_memcpy(buffer,eth_hdr,14);
 	rte_memcpy(buffer+14,pppoe_header,sizeof(pppoe_header_t));
 	rte_memcpy(buffer+14+sizeof(pppoe_header_t),ppp_payload,sizeof(ppp_payload_t));
 	rte_memcpy(buffer+14+sizeof(pppoe_header_t)+sizeof(ppp_payload_t),ppp_lcp,sizeof(ppp_lcp_header_t));
 	
	RTE_LOG(INFO,EAL,"Session 0x%x terminate ack built.\n", htons(port_ccb->session_id));
	#ifdef _DP_DBG
 	puts("terminate ack built.");
	#endif
 	return TRUE;
}

STATUS build_terminate_request(unsigned char* buffer, tPPP_PORT *port_ccb, uint16_t *mulen)
{
	struct ethhdr 			*eth_hdr = port_ccb->ppp_phase[port_ccb->cp].eth_hdr;
	pppoe_header_t 			*pppoe_header = port_ccb->ppp_phase[port_ccb->cp].pppoe_header;
	ppp_payload_t 			*ppp_payload = port_ccb->ppp_phase[port_ccb->cp].ppp_payload;
	ppp_lcp_header_t 		*ppp_lcp = port_ccb->ppp_phase[port_ccb->cp].ppp_lcp;

	rte_memcpy(eth_hdr->h_source,port_ccb->src_mac,6);
	rte_memcpy(eth_hdr->h_dest,port_ccb->dst_mac,6);
	eth_hdr->h_proto = htons(ETH_P_PPP_SES);

	/* build ppp protocol and lcp/ipcp header. */

 	pppoe_header->ver_type = VER_TYPE;
 	pppoe_header->code = 0;
 	/* We don't convert seesion id to little endian at first */
 	pppoe_header->session_id = port_ccb->session_id;

 	if (port_ccb->cp == 0) 
 		ppp_payload->ppp_protocol = htons(LCP_PROTOCOL);
 	else if (port_ccb->cp == 1)
 		ppp_payload->ppp_protocol = htons(IPCP_PROTOCOL);

 	ppp_lcp->code = TERMIN_REQUEST;
 	ppp_lcp->identifier = ((rand() % 254) + 1);

 	pppoe_header->length = sizeof(ppp_lcp_header_t) + sizeof(ppp_payload->ppp_protocol);
 	ppp_lcp->length = sizeof(ppp_lcp_header_t); 	


	*mulen = pppoe_header->length + 14 + sizeof(pppoe_header_t);
 	pppoe_header->length = htons(pppoe_header->length);
 	ppp_lcp->length = htons(ppp_lcp->length);
 	memset(buffer,0,MSG_BUF);
 	rte_memcpy(buffer,eth_hdr,14);
 	rte_memcpy(buffer+14,pppoe_header,sizeof(pppoe_header_t));
 	rte_memcpy(buffer+14+sizeof(pppoe_header_t),ppp_payload,sizeof(ppp_payload_t));
 	rte_memcpy(buffer+14+sizeof(pppoe_header_t)+sizeof(ppp_payload_t),ppp_lcp,sizeof(ppp_lcp_header_t));
 	
	RTE_LOG(INFO,EAL,"Session 0x%x terminate request built.\n", htons(port_ccb->session_id));
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

STATUS build_auth_request_pap(unsigned char* buffer, tPPP_PORT *port_ccb, uint16_t *mulen)
{
	ppp_lcp_header_t 		ppp_pap_header;
	uint8_t 				peer_id_length = strlen((const char *)(port_ccb->user_id));
	uint8_t 				peer_passwd_length = strlen((const char *)(port_ccb->passwd));
	struct ethhdr 			*eth_hdr = port_ccb->ppp_phase[port_ccb->cp].eth_hdr;
	pppoe_header_t 			*pppoe_header = port_ccb->ppp_phase[port_ccb->cp].pppoe_header;
	ppp_payload_t 			*ppp_payload = port_ccb->ppp_phase[port_ccb->cp].ppp_payload;
	ppp_lcp_header_t 		*ppp_lcp = port_ccb->ppp_phase[port_ccb->cp].ppp_lcp;

	port_ccb->phase = AUTH_PHASE;

	rte_memcpy(eth_hdr->h_source,port_ccb->src_mac,6);
	rte_memcpy(eth_hdr->h_dest,port_ccb->dst_mac,6);

	ppp_payload->ppp_protocol = htons(AUTH_PROTOCOL);
	ppp_pap_header.code = AUTH_REQUEST;
	ppp_pap_header.identifier = ppp_lcp->identifier;

	ppp_pap_header.length = 2 * sizeof(uint8_t) + peer_id_length + peer_passwd_length + sizeof(ppp_lcp_header_t);
	pppoe_header->length = ppp_pap_header.length + sizeof(ppp_payload_t);
	ppp_pap_header.length = htons(ppp_pap_header.length);
	pppoe_header->length = htons(pppoe_header->length);

	*mulen = ntohs(pppoe_header->length) + 14 + sizeof(pppoe_header_t);

	memset(buffer,0,MSG_BUF);
	rte_memcpy(buffer,eth_hdr,14);
 	rte_memcpy(buffer+14,pppoe_header,sizeof(pppoe_header_t));
 	rte_memcpy(buffer+14+sizeof(pppoe_header_t),ppp_payload,sizeof(ppp_payload_t));
 	rte_memcpy(buffer+14+sizeof(pppoe_header_t)+sizeof(ppp_payload_t),&ppp_pap_header,sizeof(ppp_lcp_header_t));
 	rte_memcpy(buffer+14+sizeof(pppoe_header_t)+sizeof(ppp_payload_t)+sizeof(ppp_lcp_header_t),&peer_id_length,sizeof(uint8_t));
 	rte_memcpy(buffer+14+sizeof(pppoe_header_t)+sizeof(ppp_payload_t)+sizeof(ppp_lcp_header_t)+sizeof(uint8_t),port_ccb->user_id,peer_id_length);
 	rte_memcpy(buffer+14+sizeof(pppoe_header_t)+sizeof(ppp_payload_t)+sizeof(ppp_lcp_header_t)+sizeof(uint8_t)+peer_id_length,&peer_passwd_length,sizeof(uint8_t));
 	rte_memcpy(buffer+14+sizeof(pppoe_header_t)+sizeof(ppp_payload_t)+sizeof(ppp_lcp_header_t)+sizeof(uint8_t)+peer_id_length+sizeof(uint8_t),port_ccb->passwd,peer_passwd_length);
 	
	RTE_LOG(INFO,EAL,"Session 0x%x pap request built.\n", htons(port_ccb->session_id));
	#ifdef _DP_DBG
 	puts("pap request built.");
	#endif 
 	return TRUE;
}

STATUS build_auth_ack_pap(unsigned char *buffer, tPPP_PORT *port_ccb, uint16_t *mulen)
{
	ppp_lcp_header_t 		ppp_pap_header;
	const char 				*login_msg = "Login ok";
	ppp_pap_ack_nak_t 		ppp_pap_ack_nak;
	unsigned char 			tmp_mac[6];
	struct ethhdr 			*eth_hdr = port_ccb->ppp_phase[port_ccb->cp].eth_hdr;
	pppoe_header_t 			*pppoe_header = port_ccb->ppp_phase[port_ccb->cp].pppoe_header;
	ppp_payload_t 			*ppp_payload = port_ccb->ppp_phase[port_ccb->cp].ppp_payload;
	ppp_lcp_header_t 		*ppp_lcp = port_ccb->ppp_phase[port_ccb->cp].ppp_lcp;

	rte_memcpy(tmp_mac,eth_hdr->h_source,6);
	rte_memcpy(eth_hdr->h_source,eth_hdr->h_dest,6);
	rte_memcpy(eth_hdr->h_dest,tmp_mac,6);

	ppp_payload->ppp_protocol = htons(AUTH_PROTOCOL);
	ppp_pap_header.code = AUTH_ACK;
	ppp_pap_header.identifier = ppp_lcp->identifier;

	ppp_pap_ack_nak.msg_length = strlen(login_msg);
	rte_memcpy(ppp_pap_ack_nak.msg,login_msg,ppp_pap_ack_nak.msg_length);

	ppp_pap_header.length = sizeof(ppp_lcp_header_t) + ppp_pap_ack_nak.msg_length + sizeof(ppp_pap_ack_nak.msg_length);
	pppoe_header->length = ppp_pap_header.length + sizeof(ppp_payload_t);
	ppp_pap_header.length = htons(ppp_pap_header.length);
	pppoe_header->length = htons(pppoe_header->length);

	*mulen = ntohs(pppoe_header->length) + 14 + sizeof(pppoe_header_t);

	memset(buffer,0,MSG_BUF);
	rte_memcpy(buffer,eth_hdr,14);
 	rte_memcpy(buffer+14,pppoe_header,sizeof(pppoe_header_t));
 	rte_memcpy(buffer+14+sizeof(pppoe_header_t),ppp_payload,sizeof(ppp_payload_t));
 	rte_memcpy(buffer+14+sizeof(pppoe_header_t)+sizeof(ppp_payload_t),&ppp_pap_header,sizeof(ppp_lcp_header_t));
 	rte_memcpy(buffer+14+sizeof(pppoe_header_t)+sizeof(ppp_payload_t)+sizeof(ppp_lcp_header_t),&ppp_pap_ack_nak,sizeof(ppp_pap_ack_nak.msg_length)+ppp_pap_ack_nak.msg_length);
 	
	RTE_LOG(INFO,EAL,"Session 0x%x pap ack built.\n", htons(port_ccb->session_id));
	#ifdef _DP_DBG
 	puts("pap ack built.");
	#endif
 	return TRUE;
}