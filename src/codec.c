#include "codec.h"

extern unsigned char *src_mac;
extern unsigned char *dst_mac;
extern uint16_t		 session_id;
extern unsigned char *user_id;
extern unsigned char *passwd;

uint8_t identifier;
uint32_t magic_num;
uint32_t ipv4 = 0;
uint32_t ipv4_gw = 0;
uint32_t primary_dns = 0;
uint32_t second_dns = 0;

/*============================ DECODE ===============================*/

/*****************************************************
 * ppp_decode_frame
 * 
 * input : pArg - mail.param
 * output: imsg, event
 * return: session ccb
 *****************************************************/
STATUS PPP_decode_frame(tPPP_MBX *mail, /*tPPP_MSG *imsg, */struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_lcp_header_t *ppp_lcp, ppp_lcp_options_t **ppp_lcp_options, uint16_t *event)
{
    uint16_t	mulen;

	if (mail->len > ETH_MTU){
	    return ERROR;
	}

	struct ethhdr *tmp_eth_hdr = (struct ethhdr *)mail->refp;
	pppoe_header_t *tmp_pppoe_header = (pppoe_header_t *)(tmp_eth_hdr + 1);

	memcpy(eth_hdr,tmp_eth_hdr,sizeof(struct ethhdr));
	memcpy(pppoe_header,tmp_pppoe_header,sizeof(pppoe_header_t));

	/* we receive pppoe discovery packet and dont need to parse for ppp payload */
	if (eth_hdr->h_proto == htons(ETH_P_PPP_DIS))
		return TRUE;
	
	ppp_payload_t *tmp_ppp_payload = (ppp_payload_t *)(tmp_pppoe_header + 1);
	ppp_lcp_header_t *tmp_ppp_lcp = (ppp_lcp_header_t *)(tmp_ppp_payload + 1);

	memcpy(ppp_payload,tmp_ppp_payload,sizeof(ppp_payload_t));
	memcpy(ppp_lcp,tmp_ppp_lcp,sizeof(ppp_lcp_header_t));
	*ppp_lcp_options = (ppp_lcp_options_t *)(tmp_ppp_lcp + 1);
	
	mulen = mail->len;
    
    if (pppoe_header->session_id != session_id) {
    	puts("recv not our PPP packet");
    	return ERROR;
    }

    mulen -= 14; //DA-MAC[6] + SA-MAC[6] + ETH-TYPE[2]
    uint16_t total_lcp_length = ntohs(ppp_lcp->length);

    /* check the ppp is in LCP, AUTH or NCP phase */
    if (ppp_payload->ppp_protocol == htons(IPCP_PROTOCOL)) {
    	if (decode_ipcp(eth_hdr,pppoe_header,ppp_payload,ppp_lcp,*ppp_lcp_options,total_lcp_length,event) == FALSE){
    		return FALSE;
    	}
    }
    else if (ppp_payload->ppp_protocol == htons(LCP_PROTOCOL)) {
		switch(ppp_lcp->code)
		{
			case CONFIG_REQUEST : 
				/* we check for if the request packet contains what we want */
				switch (check_nak_reject(CONFIG_NAK,eth_hdr,pppoe_header,ppp_payload,ppp_lcp,*ppp_lcp_options,total_lcp_length))
				{
					case ERROR:
						return FALSE;
					case 1:
						*event = E_RECV_BAD_CONFIG_REQUEST;
						return TRUE;
				}
				switch (check_nak_reject(CONFIG_REJECT,eth_hdr,pppoe_header,ppp_payload,ppp_lcp,*ppp_lcp_options,total_lcp_length))
				{
					case ERROR:
						return FALSE;
					case 1:
						*event = E_RECV_BAD_CONFIG_REQUEST;
						return TRUE;
				}
				*event = E_RECV_GOOD_CONFIG_REQUEST;
				ppp_lcp->length = htons(total_lcp_length);
				return TRUE;
			case CONFIG_ACK :
				if (ppp_lcp->identifier != identifier)
					return FALSE;
			
				/* only check magic number. Skip the bytes stored in ppp_lcp_options_t length to find magic num. */
				for (ppp_lcp_options_t *cur=*ppp_lcp_options; cur->type!=0;) {
					if (cur->type == MAGIC_NUM) {
						int i;
						for(i=cur->length-3; i>0; i--) {
							if (*(((uint8_t *)&magic_num) + i) != cur->val[i]) {
								puts("recv ppp LCP magic number error");
								return FALSE;
							}
						}
					}
					cur = (ppp_lcp_options_t *)((char *)cur + cur->length);
				}
				*event = E_RECV_CONFIG_ACK;
				return TRUE;
			case CONFIG_NAK : 
				*event = E_RECV_CONFIG_NAK_REJ;
				return TRUE;
			case CONFIG_REJECT :
				*event = E_RECV_CONFIG_NAK_REJ;
				return TRUE;
			case TERMIN_REQUEST :
				*event = E_RECV_TERMINATE_REQUEST;
				return TRUE;
			case TERMIN_ACK :
				*event = E_RECV_TERMINATE_ACK;
				return TRUE;
			case CODE_REJECT:
				*event = E_RECV_GOOD_CODE_PROTOCOL_REJECT;
				return TRUE;
			case PROTO_REJECT:
				*event = E_RECV_BAD_CODE_PROTOCOL_REJECT;
				return TRUE;
			case ECHO_REQUEST:
				*event = E_RECV_ECHO_REPLY_REQUEST_DISCARD_REQUEST;
				return TRUE;
			case ECHO_REPLY:
				*event = E_RECV_ECHO_REPLY_REQUEST_DISCARD_REQUEST;
				return TRUE;
			default :
				*event = E_RECV_UNKNOWN_CODE;
		}
	}

	/* in AUTH phase, if the packet is not what we want, then send nak packet and just close process */
	else if (ppp_payload->ppp_protocol == htons(AUTH_PROTOCOL)) {
		ppp_pap_ack_nak_t ppp_pap_ack_nak, *tmp_ppp_pap_ack_nak = (ppp_pap_ack_nak_t *)(tmp_ppp_lcp + 1);
		memcpy(&ppp_pap_ack_nak,tmp_ppp_pap_ack_nak,tmp_ppp_pap_ack_nak->msg_length + sizeof(uint8_t));
		if (ppp_lcp->code == AUTH_ACK) {
			puts("auth success.");
			return TRUE;
		}
		else if (ppp_lcp->code == AUTH_NAK) {
			unsigned char buffer[MSG_BUF];
    		uint16_t mulen;

    		if (build_terminate_request(0,buffer,eth_hdr,pppoe_header,ppp_payload,ppp_lcp,NULL,&mulen) < 0)
        		return FALSE;
    		drv_xmit(buffer,mulen);
			puts("auth fail.");
			return TRUE;
		}
	}
	else {
		puts("unknown PPP protocol");
		return FALSE;
	}
	
	return TRUE;
}

STATUS decode_ipcp(struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_lcp_header_t *ppp_lcp, ppp_lcp_options_t *ppp_lcp_options, uint16_t total_lcp_length, uint16_t *event)
{
	switch(ppp_lcp->code)
	{
		case CONFIG_REQUEST : 
			switch (check_ipcp_nak_rej(CONFIG_NAK,eth_hdr,pppoe_header,ppp_payload,ppp_lcp,ppp_lcp_options,total_lcp_length))
			{
				case ERROR:
					return FALSE;
				case 1:
					*event = E_RECV_BAD_CONFIG_REQUEST;
					return TRUE;
			}
			switch (check_ipcp_nak_rej(CONFIG_REJECT,eth_hdr,pppoe_header,ppp_payload,ppp_lcp,ppp_lcp_options,total_lcp_length))
			{
				case ERROR:
					return FALSE;
				case 1:
					*event = E_RECV_BAD_CONFIG_REQUEST;
					return TRUE;
			}
			memcpy(&ipv4_gw,ppp_lcp_options->val,sizeof(ipv4_gw));
			*event = E_RECV_GOOD_CONFIG_REQUEST;
			ppp_lcp->length = htons(total_lcp_length);
			return TRUE;
		case CONFIG_ACK :
			if (ppp_lcp->identifier != identifier)
				return FALSE;
			*event = E_RECV_CONFIG_ACK;
			memcpy(&ipv4,ppp_lcp_options->val,sizeof(ipv4));
			return TRUE;
		case CONFIG_NAK : 
			// if we receive nak packet, the option field contains correct ip address we want
			memcpy(&ipv4,ppp_lcp_options->val,4);
			*event = E_RECV_CONFIG_NAK_REJ;
			return TRUE;
		case CONFIG_REJECT :
			*event = E_RECV_CONFIG_NAK_REJ;
			return TRUE;
		case TERMIN_REQUEST :
			*event = E_RECV_TERMINATE_REQUEST;
			return TRUE;
		case TERMIN_ACK :
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

STATUS check_ipcp_nak_rej(uint8_t flag,struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_lcp_header_t *ppp_lcp, ppp_lcp_options_t *ppp_lcp_options, uint16_t total_lcp_length)
{
	ppp_lcp_options_t *tmp_buf = (ppp_lcp_options_t *)malloc(MSG_BUF*sizeof(char));
	ppp_lcp_options_t *tmp_cur = tmp_buf;
	int bool = 0;
	uint16_t tmp_total_length = 4;
	
	memset(tmp_buf,0,MSG_BUF);
	memcpy(tmp_buf,ppp_lcp_options,MSG_BUF);

	ppp_lcp->length = sizeof(ppp_lcp_header_t);
	for (ppp_lcp_options_t *cur=ppp_lcp_options; tmp_total_length<total_lcp_length; cur=(ppp_lcp_options_t *)((char *)cur + cur->length)) {
		if (flag == CONFIG_NAK) {
			if (cur->type == IP_ADDRESS && cur->val[0] == 0) {
				bool = 1;
				memcpy(tmp_cur,cur,cur->length);
				ppp_lcp->length += cur->length;
				tmp_cur = (ppp_lcp_options_t *)((char *)tmp_cur + cur->length);
			}
		}
		else {
			if (cur->type != IP_ADDRESS) {
				bool = 1;
				memcpy(tmp_cur,cur,cur->length);
				ppp_lcp->length += cur->length;
				tmp_cur = (ppp_lcp_options_t *)((char *)tmp_cur + cur->length);
			}
		}
		tmp_total_length += cur->length;
	}

	if (bool == 1) {
		memcpy(ppp_lcp_options,tmp_buf,ppp_lcp->length - 4);
		pppoe_header->length = htons((ppp_lcp->length) + sizeof(ppp_payload_t));
		ppp_lcp->length = htons(ppp_lcp->length);
		ppp_lcp->code = flag;
		free(tmp_buf);

		return 1;
	}
	free(tmp_buf);
	return 0;
}

STATUS check_nak_reject(uint8_t flag,struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_lcp_header_t *ppp_lcp, ppp_lcp_options_t *ppp_lcp_options, uint16_t total_lcp_length)
{
	ppp_lcp_options_t *tmp_buf = (ppp_lcp_options_t *)malloc(MSG_BUF*sizeof(char));
	ppp_lcp_options_t *tmp_cur = tmp_buf;
	int bool = 0;
	uint16_t tmp_total_length = 4;
	
	memset(tmp_buf,0,MSG_BUF);
	memcpy(tmp_buf,ppp_lcp_options,MSG_BUF);

	ppp_lcp->length = sizeof(ppp_lcp_header_t);
	for (ppp_lcp_options_t *cur=ppp_lcp_options; tmp_total_length<total_lcp_length; cur=(ppp_lcp_options_t *)((char *)cur + cur->length)) {
		if (flag == CONFIG_NAK) {
			if (cur->type == MRU && (cur->val[0] != 0x5 && cur->val[1] != 0x78)) {
				bool = 1;
				cur->val[0] = 0x5;
				cur->val[1] = 0x78;
				memcpy(tmp_cur,cur,cur->length);
				ppp_lcp->length += cur->length;
				tmp_cur = (ppp_lcp_options_t *)((char *)tmp_cur + cur->length);
			}
		}
		else {
			if (cur->type != MAGIC_NUM && cur->type != MRU && cur->type != AUTH) {
				bool = 1;
				memcpy(tmp_cur,cur,cur->length);
				ppp_lcp->length += cur->length;
				tmp_cur = (ppp_lcp_options_t *)((char *)tmp_cur + cur->length);
			}
		}
		tmp_total_length += cur->length;
	}

	if (bool == 1) {
		memcpy(ppp_lcp_options,tmp_buf,ppp_lcp->length - 4);
		pppoe_header->length = htons((ppp_lcp->length) + sizeof(ppp_payload_t));
		ppp_lcp->length = htons(ppp_lcp->length);
		ppp_lcp->code = flag;
		free(tmp_buf);

		return 1;
	}
	free(tmp_buf);
	return 0;
}

STATUS pppoe_recv(tPPP_MBX *mail, struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header)
{
	pppoe_header_tag_t *pppoe_header_tag = (pppoe_header_tag_t *)((pppoe_header_t *)((struct ethhdr *)mail->refp + 1) + 1);

	switch(pppoe_header->code) {
		case PADO:
			memcpy(src_mac,eth_hdr->h_dest,6);
			memcpy(dst_mac,eth_hdr->h_source,6);
			if (build_padr(eth_hdr,pppoe_header,pppoe_header_tag) == FALSE)
				return FALSE;
			return TRUE;
		case PADS:
			session_id = pppoe_header->session_id;
			return TRUE;
		case PADT:
			puts("Connection disconnected.");
			return FALSE;
		default:
			puts("Unknown PPPoE discovery type.");
			return FALSE;
	}
}

STATUS build_padi(void)
{
	unsigned char buffer[MSG_BUF];
	uint16_t mulen;
	struct ethhdr eth_hdr;
	pppoe_header_t 		pppoe_header;
	pppoe_header_tag_t 	pppoe_header_tag;

	for (int i=0; i<6; i++) {
 		eth_hdr.h_source[i] = src_mac[i];
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

	memcpy(buffer,&eth_hdr,sizeof(struct ethhdr));
	memcpy(buffer+sizeof(struct ethhdr),&pppoe_header,sizeof(pppoe_header_t));
	memcpy(buffer+sizeof(struct ethhdr)+sizeof(pppoe_header_t),&pppoe_header_tag,sizeof(pppoe_header_tag_t));
	drv_xmit(buffer,mulen);

	return TRUE;
}

/* rebuild pppoe tag */
STATUS build_padr(struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header, pppoe_header_tag_t *pppoe_header_tag)
{
	unsigned char buffer[MSG_BUF];
	uint16_t mulen;
	pppoe_header_tag_t *tmp_pppoe_header_tag = (pppoe_header_tag_t *)((pppoe_header_t *)((struct ethhdr *)buffer + 1) + 1);

	memcpy(eth_hdr->h_source,src_mac,6);
 	memcpy(eth_hdr->h_dest,dst_mac,6);
 	pppoe_header->code = PADR;

 	uint32_t total_tag_length = 0;
	for(pppoe_header_tag_t *cur = tmp_pppoe_header_tag;;) {
		cur->type = pppoe_header_tag->type;
		cur->length = pppoe_header_tag->length;
		switch(ntohs(pppoe_header_tag->type)) {
			case END_OF_LIST:
				break;
			case SERVICE_NAME:
				break;
			case AC_NAME:
				/* We dont need to add ac-name tag to PADR. */
				pppoe_header_tag = (pppoe_header_tag_t *)((char *)pppoe_header_tag + 4 + ntohs(pppoe_header_tag->length));
				continue;
			case HOST_UNIQ:
			case AC_COOKIE:
			case RELAY_ID:
				if (cur->length != 0)
					memcpy(cur->value,pppoe_header_tag->value,ntohs(cur->length));
				break;
			case GENERIC_ERROR:
				puts("PPPoE discover generic error");
				return FALSE;
			default:
				perror("Unknown PPPOE tag value"); 
		}
		if (ntohs(pppoe_header_tag->type) == END_OF_LIST)
			break;

		/* to caculate total pppoe header tags' length, we need to add tag type and tag length field in each tag scanning. */
		total_tag_length = ntohs(cur->length) + 4 + total_tag_length;
		/* Fetch next tag field. */
		pppoe_header_tag = (pppoe_header_tag_t *)((char *)pppoe_header_tag + 4 + ntohs(pppoe_header_tag->length));
		cur = (pppoe_header_tag_t *)((char *)cur + 4 + ntohs(cur->length));
	}

	pppoe_header->length = htons(total_tag_length);
	mulen = sizeof(struct ethhdr) + sizeof(pppoe_header_t) + total_tag_length;

	memcpy(buffer,eth_hdr,sizeof(struct ethhdr));
	memcpy(buffer+sizeof(struct ethhdr),pppoe_header,sizeof(pppoe_header_t));
	memcpy(buffer+sizeof(struct ethhdr)+sizeof(pppoe_header_t),tmp_pppoe_header_tag,total_tag_length);
	drv_xmit(buffer,mulen);

	return TRUE;
}

STATUS build_padt(struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header)
{
	unsigned char buffer[MSG_BUF];
	uint16_t mulen;

	memcpy(eth_hdr->h_source,src_mac,6);
 	memcpy(eth_hdr->h_dest,dst_mac,6);
 	eth_hdr->h_proto = htons(ETH_P_PPP_DIS);

	pppoe_header->ver_type = VER_TYPE;
	pppoe_header->code = PADT;
	pppoe_header->session_id = session_id; 
	pppoe_header->length = 0;

	mulen = sizeof(struct ethhdr) + sizeof(pppoe_header_t);

	memcpy(buffer,eth_hdr,sizeof(struct ethhdr));
	memcpy(buffer+sizeof(struct ethhdr),pppoe_header,sizeof(pppoe_header_t));
	drv_xmit(buffer,mulen);

	return TRUE;
}

STATUS build_config_request(int cp, unsigned char *buffer, struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_lcp_header_t *ppp_lcp, ppp_lcp_options_t *ppp_lcp_options, uint16_t *mulen)
{
	srand(time(NULL));

	memcpy(eth_hdr->h_source,src_mac,6);
	memcpy(eth_hdr->h_dest,dst_mac,6);
	eth_hdr->h_proto = htons(ETH_P_PPP_SES);

	/* build ppp protocol and lcp header. */

 	pppoe_header->ver_type = VER_TYPE;
 	pppoe_header->code = 0;
 	pppoe_header->session_id = session_id; /* We didnt convert seesion id to little endian at first */

 	ppp_lcp->code = CONFIG_REQUEST;
 	ppp_lcp->identifier = ((rand() % 254) + 1);

 	identifier = ppp_lcp->identifier;

 	pppoe_header->length = sizeof(ppp_lcp_header_t) + sizeof(ppp_payload->ppp_protocol);
 	ppp_lcp->length = sizeof(ppp_lcp_header_t);

 	if (cp == 1) {
 		ppp_payload->ppp_protocol = htons(IPCP_PROTOCOL);
 		ppp_lcp_options->type = IP_ADDRESS;
 		memcpy(ppp_lcp_options->val,&ipv4,4);
 		ppp_lcp_options->length = sizeof(ipv4) + sizeof(ppp_lcp_options_t);
 		pppoe_header->length += ppp_lcp_options->length;
 		ppp_lcp->length += ppp_lcp_options->length;
 	}
 	else if (cp == 0) {
 		ppp_payload->ppp_protocol = htons(LCP_PROTOCOL);
 		/* options, max recv units */
 		ppp_lcp_options_t *cur = ppp_lcp_options;

 		cur->type = MRU;
 		cur->length = 0x4;
 		uint16_t max_recv_unit = htons(MAX_RECV);
 		memcpy(cur->val,&max_recv_unit,sizeof(uint16_t));
 		pppoe_header->length += 4;
 		ppp_lcp->length += 4;

 		/* option, auth*/
 		cur = (ppp_lcp_options_t *)((char *)(cur + 1) + sizeof(max_recv_unit));
 		cur->type = 0x3;
 		cur->length = 0x4;
 		uint16_t auth_pro = htons(AUTH_PROTOCOL);
 		memcpy(cur->val,&auth_pro,sizeof(uint16_t));
 		pppoe_header->length += 4;
 		ppp_lcp->length += 4;

 		/* options, magic number */
 		cur = (ppp_lcp_options_t *)((char *)(cur + 1) + sizeof(auth_pro));

 		cur->type = MAGIC_NUM;
 		cur->length = 0x6;
 		magic_num = htonl((rand() % 0xFFFFFFFE) + 1);
 		memcpy(cur->val,&magic_num,sizeof(uint32_t));
 		pppoe_header->length += 6;
 		ppp_lcp->length += 6;
	}

	*mulen = pppoe_header->length + 14 + sizeof(pppoe_header_t);

 	pppoe_header->length = htons(pppoe_header->length);
 	ppp_lcp->length = htons(ppp_lcp->length);
 	memset(buffer,0,MSG_BUF);
 	memcpy(buffer,eth_hdr,14);
 	memcpy(buffer+14,pppoe_header,sizeof(pppoe_header_t));
 	memcpy(buffer+14+sizeof(pppoe_header_t),ppp_payload,sizeof(ppp_payload_t));
 	memcpy(buffer+14+sizeof(pppoe_header_t)+sizeof(ppp_payload_t),ppp_lcp,sizeof(ppp_lcp_header_t));
 	memcpy(buffer+14+sizeof(pppoe_header_t)+sizeof(ppp_payload_t)+sizeof(ppp_lcp_header_t),ppp_lcp_options,htons(ppp_lcp->length) - sizeof(ppp_lcp_header_t));

 	puts("config request built.");
 	PRINT_MESSAGE(buffer,*mulen);
 	return TRUE;
}

STATUS build_config_ack(int cp, unsigned char* buffer, struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_lcp_header_t *ppp_lcp, ppp_lcp_options_t *ppp_lcp_options, uint16_t *mulen)
{
	ppp_lcp->code = CONFIG_ACK;

	memcpy(eth_hdr->h_source,src_mac,6);
	memcpy(eth_hdr->h_dest,dst_mac,6);

	*mulen = ntohs(pppoe_header->length) + 14 + sizeof(pppoe_header_t);

	memset(buffer,0,MSG_BUF);
	memcpy(buffer,eth_hdr,14);
 	memcpy(buffer+14,pppoe_header,sizeof(pppoe_header_t));
 	memcpy(buffer+14+sizeof(pppoe_header_t),ppp_payload,sizeof(ppp_payload_t));
 	memcpy(buffer+14+sizeof(pppoe_header_t)+sizeof(ppp_payload_t),ppp_lcp,sizeof(ppp_lcp_header_t));
 	memcpy(buffer+14+sizeof(pppoe_header_t)+sizeof(ppp_payload_t)+sizeof(ppp_lcp_header_t),ppp_lcp_options,htons(ppp_lcp->length) - sizeof(ppp_lcp_header_t));

 	puts("config ack built.");
 	return TRUE;
}

STATUS build_config_nak_rej(int cp, unsigned char* buffer, struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_lcp_header_t *ppp_lcp, ppp_lcp_options_t *ppp_lcp_options, uint16_t *mulen)
{
	memcpy(eth_hdr->h_source,src_mac,6);
	memcpy(eth_hdr->h_dest,dst_mac,6);

	*mulen = ntohs(pppoe_header->length) + 14 + sizeof(pppoe_header_t);

	memset(buffer,0,MSG_BUF);
	memcpy(buffer,eth_hdr,14);
 	memcpy(buffer+14,pppoe_header,sizeof(pppoe_header_t));
 	memcpy(buffer+14+sizeof(pppoe_header_t),ppp_payload,sizeof(ppp_payload_t));
 	memcpy(buffer+14+sizeof(pppoe_header_t)+sizeof(ppp_payload_t),ppp_lcp,sizeof(ppp_lcp_header_t));
 	memcpy(buffer+14+sizeof(pppoe_header_t)+sizeof(ppp_payload_t)+sizeof(ppp_lcp_header_t),ppp_lcp_options,ntohs(ppp_lcp->length) - sizeof(ppp_lcp_header_t));

 	puts("config nak/rej built.");
 	return TRUE;
}

STATUS build_echo_reply(unsigned char* buffer, struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_lcp_header_t *ppp_lcp, ppp_lcp_options_t *ppp_lcp_options, uint16_t *mulen)
{
	ppp_lcp->code = ECHO_REPLY;

	memcpy(eth_hdr->h_source,src_mac,6);
	memcpy(eth_hdr->h_dest,dst_mac,6);

	*mulen = ntohs(pppoe_header->length) + 14 + sizeof(pppoe_header_t);

	memset(buffer,0,MSG_BUF);
	memcpy(buffer,eth_hdr,14);
 	memcpy(buffer+14,pppoe_header,sizeof(pppoe_header_t));
 	memcpy(buffer+14+sizeof(pppoe_header_t),ppp_payload,sizeof(ppp_payload_t));
 	memcpy(buffer+14+sizeof(pppoe_header_t)+sizeof(ppp_payload_t),ppp_lcp,sizeof(ppp_lcp_header_t));
 	memcpy(buffer+14+sizeof(pppoe_header_t)+sizeof(ppp_payload_t)+sizeof(ppp_lcp_header_t),ppp_lcp_options,htons(ppp_lcp->length) - sizeof(ppp_lcp_header_t));

 	puts("echo reply built.");
 	return TRUE;
}

STATUS build_terminate_ack(int cp, unsigned char* buffer, struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_lcp_header_t *ppp_lcp, ppp_lcp_options_t *ppp_lcp_options, uint16_t *mulen)
{
	ppp_lcp->code = TERMIN_ACK;

	memcpy(eth_hdr->h_source,src_mac,6);
	memcpy(eth_hdr->h_dest,dst_mac,6);

	*mulen = ntohs(pppoe_header->length) + 14 + sizeof(pppoe_header_t);

	memset(buffer,0,MSG_BUF);
	memcpy(buffer,eth_hdr,14);
 	memcpy(buffer+14,pppoe_header,sizeof(pppoe_header_t));
 	memcpy(buffer+14+sizeof(pppoe_header_t),ppp_payload,sizeof(ppp_payload_t));
 	memcpy(buffer+14+sizeof(pppoe_header_t)+sizeof(ppp_payload_t),ppp_lcp,sizeof(ppp_lcp_header_t));
 	
 	puts("terminate ack built.");
 	return TRUE;
}

STATUS build_terminate_request(int cp, unsigned char* buffer, struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_lcp_header_t *ppp_lcp, ppp_lcp_options_t *ppp_lcp_options, uint16_t *mulen)
{
	memcpy(eth_hdr->h_dest,src_mac,6);
	memcpy(eth_hdr->h_source,dst_mac,6);
	eth_hdr->h_proto = htons(ETH_P_PPP_SES);

	/* build ppp protocol and lcp header. */

 	pppoe_header->ver_type = VER_TYPE;
 	pppoe_header->code = 0;
 	pppoe_header->session_id = session_id; /* We didnt convert seesion id to little endian at first */

 	ppp_payload->ppp_protocol = htons(LCP_PROTOCOL);

 	ppp_lcp->code = TERMIN_REQUEST;
 	ppp_lcp->identifier = ((rand() % 254) + 1);

 	pppoe_header->length = sizeof(ppp_lcp_header_t) + sizeof(ppp_payload->ppp_protocol);
 	ppp_lcp->length = sizeof(ppp_lcp_header_t); 	


	*mulen = pppoe_header->length + 14 + sizeof(pppoe_header_t);
 	pppoe_header->length = htons(pppoe_header->length);
 	ppp_lcp->length = htons(ppp_lcp->length);
 	memset(buffer,0,MSG_BUF);
 	memcpy(buffer,eth_hdr,14);
 	memcpy(buffer+14,pppoe_header,sizeof(pppoe_header_t));
 	memcpy(buffer+14+sizeof(pppoe_header_t),ppp_payload,sizeof(ppp_payload_t));
 	memcpy(buffer+14+sizeof(pppoe_header_t)+sizeof(ppp_payload_t),ppp_lcp,sizeof(ppp_lcp_header_t));
 	
	puts("build terminate request.");

 	return TRUE;
}

STATUS build_code_reject(int cp, unsigned char* buffer, struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_lcp_header_t *ppp_lcp, ppp_lcp_options_t *ppp_lcp_options, uint16_t *mulen)
{
	puts("build code reject.");

	return TRUE;
}

STATUS build_auth_request_pap(unsigned char* buffer, struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_lcp_header_t *ppp_lcp, ppp_lcp_options_t *ppp_lcp_options, uint16_t *mulen)
{
	ppp_lcp_header_t ppp_pap_header;
	uint8_t peer_id_length = strlen(user_id);
	uint8_t peer_passwd_length = strlen(passwd);
	
	memcpy(eth_hdr->h_source,src_mac,6);
	memcpy(eth_hdr->h_dest,dst_mac,6);

	ppp_payload->ppp_protocol = htons(AUTH_PROTOCOL);
	ppp_pap_header.code = AUTH_REQUEST;
	ppp_pap_header.identifier = ppp_lcp->identifier;

	ppp_pap_header.length = 2 * sizeof(uint8_t) + peer_id_length + peer_passwd_length + sizeof(ppp_lcp_header_t);
	pppoe_header->length = ppp_pap_header.length + sizeof(ppp_payload_t);
	ppp_pap_header.length = htons(ppp_pap_header.length);
	pppoe_header->length = htons(pppoe_header->length);

	*mulen = ntohs(pppoe_header->length) + 14 + sizeof(pppoe_header_t);

	memset(buffer,0,MSG_BUF);
	memcpy(buffer,eth_hdr,14);
 	memcpy(buffer+14,pppoe_header,sizeof(pppoe_header_t));
 	memcpy(buffer+14+sizeof(pppoe_header_t),ppp_payload,sizeof(ppp_payload_t));
 	memcpy(buffer+14+sizeof(pppoe_header_t)+sizeof(ppp_payload_t),&ppp_pap_header,sizeof(ppp_lcp_header_t));
 	memcpy(buffer+14+sizeof(pppoe_header_t)+sizeof(ppp_payload_t)+sizeof(ppp_lcp_header_t),&peer_id_length,sizeof(uint8_t));
 	memcpy(buffer+14+sizeof(pppoe_header_t)+sizeof(ppp_payload_t)+sizeof(ppp_lcp_header_t)+sizeof(uint8_t),user_id,peer_id_length);
 	memcpy(buffer+14+sizeof(pppoe_header_t)+sizeof(ppp_payload_t)+sizeof(ppp_lcp_header_t)+sizeof(uint8_t)+peer_id_length,&peer_passwd_length,sizeof(uint8_t));
 	memcpy(buffer+14+sizeof(pppoe_header_t)+sizeof(ppp_payload_t)+sizeof(ppp_lcp_header_t)+sizeof(uint8_t)+peer_id_length+sizeof(uint8_t),passwd,peer_passwd_length);
 	
 	puts("pap request built.");
 	return TRUE;
}