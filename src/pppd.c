/*\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\
  PPPD.C

    - purpose : for ppp detection
	
  Designed by THE on Jan 14, 2019
/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\*/

#include        		<common.h>
#include 				<rte_eal.h>
#include 				<rte_ethdev.h>
#include 				<rte_cycles.h>
#include 				<rte_lcore.h>
#include 				<rte_timer.h>
#include				<rte_malloc.h>
#include 				<rte_ether.h>
#include 				<rte_log.h>
#include 				<cmdline_rdline.h>
#include 				<cmdline_parse.h>
#include 				<cmdline_parse_string.h>
#include 				<cmdline_socket.h>
#include 				<cmdline.h>

#include				<rte_memcpy.h>
#include 				<rte_flow.h>
#include				<rte_atomic.h>
#include				<rte_pdump.h>
#include 				<rte_trace.h>
#include 				<sys/mman.h>
#include 				"pppd.h"
#include				"fsm.h"
#include 				"dp.h"
#include 				"dbg.h"
#include				"cmds.h"
#include				"init.h"
#include				"dp_flow.h"
#include 				"dhcpd.h"
#include				"vrg.h"

U32						ppp_interval;
static VRG_t			*vrg_ccb;
extern struct lcore_map lcore;

extern STATUS			PPP_FSM(struct rte_timer *ppp, PPP_INFO_t *ppp_ccb, U16 event);

/**
 * @brief pppoe connection closing processing function
 * 
 * @param s_ppp_ccb 
 */
void PPP_bye(PPP_INFO_t *s_ppp_ccb)
{
	rte_timer_stop(&(s_ppp_ccb->ppp));
	rte_timer_stop(&(s_ppp_ccb->pppoe));
	rte_timer_stop(&(s_ppp_ccb->ppp_alive));
	rte_atomic16_cmpset((volatile uint16_t *)&s_ppp_ccb->dp_start_bool.cnt, (BIT16)1, (BIT16)0);
   	switch(s_ppp_ccb->phase) {
		case END_PHASE:
			rte_atomic16_set(&s_ppp_ccb->ppp_bool, 0);
			s_ppp_ccb->ppp_processing = FALSE;
			if ((--vrg_ccb->cur_user) == 0) {
				if (vrg_ccb->quit_flag == TRUE) {
					rte_ring_free(rte_ring);
					rte_ring_free(uplink_q);
					rte_ring_free(downlink_q);
					rte_ring_free(gateway_q);
            		fclose(vrg_ccb->fp);
					cmdline_stdin_exit(vrg_ccb->cl);
					munmap(vrg_ccb->ppp_ccb, sizeof(PPP_INFO_t)*vrg_ccb->user_count);
					munmap(vrg_ccb->dhcp_ccb, sizeof(dhcp_ccb_t)*vrg_ccb->user_count);
					//rte_mempool_put_bulk(vrg_ccb.ppp_ccb_mp, (void *const *)&vrg_ccb.ppp_ccb, user_count);
					//rte_mempool_free(vrg_ccb.ppp_ccb_mp);
					#ifdef RTE_LIBRTE_PDUMP
					/*uninitialize packet capture framework */
					rte_pdump_uninit();
					#endif
					rte_trace_save();
					puts("Bye!");
					exit(0);
				}
			}
			break;
   		case PPPOE_PHASE:
			s_ppp_ccb->phase--;
			s_ppp_ccb->ppp_phase[0].state = S_INIT;
			s_ppp_ccb->ppp_phase[1].state = S_INIT;
		   	PPP_bye(s_ppp_ccb);
    		break;
    	case LCP_PHASE:
			s_ppp_ccb->ppp_processing = TRUE;
    		s_ppp_ccb->cp = 0;
			s_ppp_ccb->ppp_phase[1].state = S_INIT;
    		PPP_FSM(&(s_ppp_ccb->ppp), s_ppp_ccb, E_CLOSE);
    		break;
    	case DATA_PHASE:
			/* modify pppoe phase from DATA_PHASE to IPCP_PHASE */
    		s_ppp_ccb->phase--;
    	case IPCP_PHASE:
			s_ppp_ccb->ppp_processing = TRUE;
			/* set ppp control protocol to IPCP */
    		s_ppp_ccb->cp = 1;
    		PPP_FSM(&(s_ppp_ccb->ppp), s_ppp_ccb, E_CLOSE);
    		break;
    	default:
    		;
    }
}

/*---------------------------------------------------------
 * ppp_int : signal handler for INTR-C only
 *--------------------------------------------------------*/
void PPP_int()
{
    printf("vRG system interupt!\n");
    rte_ring_free(rte_ring);
	rte_ring_free(uplink_q);
	rte_ring_free(downlink_q);
	rte_ring_free(gateway_q);
    fclose(vrg_ccb->fp);
	cmdline_stdin_exit(vrg_ccb->cl);
	printf("bye!\n");
	exit(0);
}

/**
 * @brief pppd init function
 * @return int 
 */
STATUS pppdInit(void *ccb)
{	
	vrg_ccb = (void *)ccb;

	vrg_ccb->ppp_ccb = mmap(NULL, sizeof(PPP_INFO_t)*vrg_ccb->user_count, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
	if (vrg_ccb->ppp_ccb == MAP_FAILED) { 
		VRG_LOG(ERR, NULL, NULL, PPPLOGMSG, "mmap ppp_ccb failed: %s", strerror(errno));
		vrg_ccb->ppp_ccb = NULL;
		return ERROR;
	}

	PPP_INFO_t *ppp_ccb = vrg_ccb->ppp_ccb;
	ppp_interval = (uint32_t)(3*SECOND); 

    for(int i=0; i<vrg_ccb->user_count; i++) {
		ppp_ccb[i].ppp_phase[0].state = S_INIT;
		ppp_ccb[i].ppp_phase[1].state = S_INIT;
		ppp_ccb[i].pppoe_phase.active = FALSE;
		/* subscriptor id starts from 1 */
		ppp_ccb[i].user_num = i + 1;
		/* vlan of each subscriptor is adding the base_vlan value in vRG_setup file to i */
		ppp_ccb[i].vlan = i + vrg_ccb->base_vlan;
		
		ppp_ccb[i].hsi_ipv4 = 0;
		ppp_ccb[i].hsi_ipv4_gw = 0;
		ppp_ccb[i].hsi_primary_dns = 0;
		ppp_ccb[i].hsi_second_dns = 0;
		ppp_ccb[i].phase = END_PHASE;
		ppp_ccb[i].is_pap_auth = FALSE;
		ppp_ccb[i].auth_method = CHAP_PROTOCOL;
		for(int j=0; j<TOTAL_SOCK_PORT; j++) {
			rte_atomic16_init(&ppp_ccb[i].addr_table[j].is_alive);
			rte_atomic16_init(&ppp_ccb[i].addr_table[j].is_fill);
		}
		memset(ppp_ccb[i].PPP_dst_mac.addr_bytes, 0, ETH_ALEN);
		rte_timer_init(&(ppp_ccb[i].pppoe));
		rte_timer_init(&(ppp_ccb[i].ppp));
		rte_timer_init(&(ppp_ccb[i].nat));
		rte_timer_init(&(ppp_ccb[i].ppp_alive));
		rte_atomic16_init(&ppp_ccb[i].dp_start_bool);
		rte_atomic16_init(&ppp_ccb[i].ppp_bool);
		ppp_ccb[i].ppp_user_id = (unsigned char *)"asdf";
		ppp_ccb[i].ppp_passwd = (unsigned char *)"zxcv";
	}
    
	sleep(1);
	VRG_LOG(INFO, NULL, NULL, PPPLOGMSG, "============ pppoe init successfully ==============\n");
	return SUCCESS;
}

void exit_ppp(__attribute__((unused)) struct rte_timer *tim, PPP_INFO_t *ppp_ccb)
{
	rte_atomic16_cmpset((U16 *)&(ppp_ccb->ppp_bool.cnt), 1, 0);
	rte_timer_stop(&(ppp_ccb->ppp));
	rte_timer_stop(&(ppp_ccb->pppoe));
	rte_timer_stop(&(ppp_ccb->ppp_alive));
	if (ppp_ccb->phase > END_PHASE)
		vrg_ccb->cur_user--;
	ppp_ccb->phase = END_PHASE;
	ppp_ccb->ppp_phase[0].state = S_INIT;
	ppp_ccb->ppp_phase[1].state = S_INIT;
	ppp_ccb->pppoe_phase.active = FALSE;
}

/**
 * @brief PPPoE / PPP protocol processing
 * 
 * @param mail 
 * @retval TURE if process successfully
 * @retval FALSE if process failed
 */
STATUS ppp_process(void	*mail)
{
	tVRG_MBX	*vrg_mail = (tVRG_MBX *)mail;
	PPP_INFO_t			*ppp_ccb = vrg_ccb->ppp_ccb;
	int 				cp, ret;
	uint16_t			event, session_index = 0;
	struct rte_ether_hdr eth_hdr;
	vlan_header_t		vlan_header;
	pppoe_header_t 		pppoe_header;
	ppp_payload_t		ppp_payload;
	ppp_header_t		ppp_hdr;
	ppp_options_t		*ppp_options = (ppp_options_t *)rte_malloc(NULL,40*sizeof(char),0);

	#pragma GCC diagnostic push  // require GCC 4.6
	#pragma GCC diagnostic ignored "-Wstrict-aliasing"
	session_index = ((vlan_header_t *)(((struct rte_ether_hdr *)vrg_mail->refp) + 1))->tci_union.tci_value;
	session_index = rte_be_to_cpu_16(session_index);
	session_index = (session_index & 0xFFF) - vrg_ccb->base_vlan;
	if (session_index >= vrg_ccb->user_count) {
		#ifdef _DP_DBG
		puts("Recv not our PPPoE packet.\nDiscard.");
		#endif
		return FALSE;
	}
	#pragma GCC diagnostic pop   // require GCC 4.6
	ret = PPP_decode_frame(vrg_mail, &eth_hdr, &vlan_header, &pppoe_header, &ppp_payload, &ppp_hdr, ppp_options, &event ,&ppp_ccb[session_index]);
	if (ret == ERROR)					
		return FALSE;
	if (ret == FALSE) {
		switch(pppoe_header.code) {
		case PADO:
			if (ppp_ccb[session_index].pppoe_phase.active == TRUE)
				return FALSE;
			ppp_ccb[session_index].pppoe_phase.active = TRUE;
    		ppp_ccb[session_index].pppoe_phase.eth_hdr = &eth_hdr;
			ppp_ccb[session_index].pppoe_phase.vlan_header = &vlan_header;
			ppp_ccb[session_index].pppoe_phase.pppoe_header = &pppoe_header;
			ppp_ccb[session_index].pppoe_phase.pppoe_header_tag = (pppoe_header_tag_t *)((pppoe_header_t *)((vlan_header_t *)((struct rte_ether_hdr *)vrg_mail->refp + 1) + 1) + 1);
			ppp_ccb[session_index].pppoe_phase.max_retransmit = MAX_RETRAN;
			ppp_ccb[session_index].pppoe_phase.timer_counter = 0;
			rte_timer_stop(&(ppp_ccb[session_index].pppoe));
			rte_ether_addr_copy(&eth_hdr.src_addr, &ppp_ccb[session_index].PPP_dst_mac);
			if (build_padr(&(ppp_ccb[session_index].pppoe),&(ppp_ccb[session_index])) == FALSE) {
				exit_ppp(&(ppp_ccb[session_index].pppoe), &(ppp_ccb[session_index]));
				return FALSE;
			}
			rte_timer_reset(&(ppp_ccb[session_index].pppoe),rte_get_timer_hz(),PERIODICAL,lcore.timer_thread,(rte_timer_cb_t)build_padr,&ppp_ccb[session_index]);
			return FALSE;
		case PADS:
			rte_timer_stop(&(ppp_ccb[session_index].pppoe));
			ppp_ccb[session_index].session_id = pppoe_header.session_id;
			ppp_ccb[session_index].cp = 0;
    		for (int i=0; i<2; i++) {
    			ppp_ccb[session_index].ppp_phase[i].eth_hdr = &eth_hdr;
				ppp_ccb[session_index].ppp_phase[i].vlan_header = &vlan_header;
    			ppp_ccb[session_index].ppp_phase[i].pppoe_header = &pppoe_header;
    			ppp_ccb[session_index].ppp_phase[i].ppp_payload = &ppp_payload;
    			ppp_ccb[session_index].ppp_phase[i].ppp_hdr = &ppp_hdr;
    			ppp_ccb[session_index].ppp_phase[i].ppp_options = ppp_options;
   			}
    		PPP_FSM(&(ppp_ccb[session_index].ppp),&ppp_ccb[session_index],E_OPEN);
			return FALSE;
		case PADT:
			for(session_index=0; session_index<vrg_ccb->user_count; session_index++) {
				if (ppp_ccb[session_index].session_id == pppoe_header.session_id)
					break;
    		}
    		if (session_index == vrg_ccb->user_count) {
				RTE_LOG(INFO,EAL,"Out of range session id in PADT.\n");
				#ifdef _DP_DBG
    			puts("Out of range session id in PADT.");
				#endif
    			return FALSE;
    		}
    		ppp_ccb[session_index].pppoe_phase.eth_hdr = &eth_hdr;
			ppp_ccb[session_index].pppoe_phase.pppoe_header = &pppoe_header;
			ppp_ccb[session_index].pppoe_phase.pppoe_header_tag = (pppoe_header_tag_t *)((pppoe_header_t *)((struct rte_ether_hdr *)vrg_mail->refp + 1) + 1);
			ppp_ccb[session_index].pppoe_phase.max_retransmit = MAX_RETRAN;
						
			#ifdef _DP_DBG
			printf("Session 0x%x connection disconnected.\n", rte_be_to_cpu_16(ppp_ccb[session_index].session_id));
			#endif
			RTE_LOG(INFO,EAL,"Session 0x%x connection disconnected.\n",rte_be_to_cpu_16(ppp_ccb[session_index].session_id));
			ppp_ccb[session_index].phase = END_PHASE;
			ppp_ccb[session_index].pppoe_phase.active = FALSE;
			PPP_bye(&ppp_ccb[session_index]);
			return FALSE;		
		case PADM:
			RTE_LOG(INFO,EAL,"recv active discovery message\n");
			return FALSE;
		default:
			RTE_LOG(INFO,EAL,"Unknown PPPoE discovery type %x.\n", pppoe_header.code);
			#ifdef _DP_DBG
			puts("Unknown PPPoE discovery type.");
			#endif
			return FALSE;
		}
	}
	ppp_ccb[session_index].ppp_phase[0].ppp_options = ppp_options;
	ppp_ccb[session_index].ppp_phase[1].ppp_options = ppp_options;
	if (ppp_payload.ppp_protocol == rte_cpu_to_be_16(PAP_PROTOCOL) || ppp_payload.ppp_protocol == rte_cpu_to_be_16(CHAP_PROTOCOL)) {
		if (ppp_hdr.code == PAP_NAK || ppp_hdr.code == CHAP_FAILURE) {
			RTE_LOG(INFO,EAL,"User %" PRIu16 " received auth info error and start closing connection.\n", ppp_ccb[session_index].user_num);
    		ppp_ccb[session_index].cp = 0;
    		ppp_ccb[session_index].phase--;
    		PPP_FSM(&(ppp_ccb[session_index].ppp),&ppp_ccb[session_index],E_CLOSE);
		}
		else if (ppp_hdr.code == PAP_ACK || ppp_hdr.code == CHAP_SUCCESS) {
			ppp_ccb[session_index].cp = 1;
			PPP_FSM(&(ppp_ccb[session_index].ppp),&ppp_ccb[session_index],E_OPEN);
			return FALSE;
		}
	}
	cp = (ppp_payload.ppp_protocol == rte_cpu_to_be_16(IPCP_PROTOCOL)) ? 1 : 0;
	ppp_ccb[session_index].cp = cp;
	PPP_FSM(&(ppp_ccb[session_index].ppp), &ppp_ccb[session_index], event);
	
	return TRUE;
}
