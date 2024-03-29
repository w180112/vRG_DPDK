/*\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\
  PPPD.C

    - purpose : for ppp detection
	
  Designed by THE on Jan 14, 2019
/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\*/

#include <common.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_timer.h>
#include <rte_ether.h>
#include <rte_memcpy.h>
#include <rte_flow.h>
#include <rte_atomic.h>
#include <rte_pdump.h>
#include <rte_trace.h>
#include <sys/mman.h>
#include "pppd.h"
#include "fsm.h"
#include "../dp.h"
#include "../dbg.h"
#include "../init.h"
#include "../dp_flow.h"
#include "../dhcpd/dhcpd.h"
#include "../vrg.h"
#include "../utils.h"

U32	            ppp_interval;
static VRG_t    *vrg_ccb;

extern STATUS   PPP_FSM(struct rte_timer *ppp, PPP_INFO_t *ppp_ccb, U16 event);

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
					close(vrg_ccb->unix_sock_fd);
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

/**
 * @brief pppd init function
 * @return int 
 */
STATUS pppd_init(void *ccb)
{	
	vrg_ccb = (VRG_t *)ccb;

	vrg_ccb->ppp_ccb = mmap(NULL, sizeof(PPP_INFO_t)*vrg_ccb->user_count, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
	if (vrg_ccb->ppp_ccb == MAP_FAILED) { 
		VRG_LOG(ERR, vrg_ccb->fp, NULL, PPPLOGMSG, "mmap ppp_ccb failed: %s", strerror(errno));
		vrg_ccb->ppp_ccb = NULL;
		return ERROR;
	}

	srand(time(NULL));

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
		
		ppp_ccb[i].hsi_ipv4 = 0x0;
		ppp_ccb[i].hsi_ipv4_gw = 0x0;
		ppp_ccb[i].hsi_primary_dns = 0x0;
		ppp_ccb[i].hsi_second_dns = 0x0;
		ppp_ccb[i].phase = END_PHASE;
		ppp_ccb[i].is_pap_auth = FALSE;
		ppp_ccb[i].auth_method = CHAP_PROTOCOL;
		ppp_ccb[i].magic_num = rte_cpu_to_be_32((rand() % 0xFFFFFFFE) + 1);
		ppp_ccb[i].identifier = 0x0;
		for(int j=0; j<TOTAL_SOCK_PORT; j++) {
			rte_atomic16_init(&ppp_ccb[i].addr_table[j].is_alive);
			rte_atomic16_init(&ppp_ccb[i].addr_table[j].is_fill);
		}
		memset(ppp_ccb[i].PPP_dst_mac.addr_bytes, 0, ETH_ALEN);
		//ppp_ccb[i].fp = vrg_ccb->fp;
		rte_timer_init(&(ppp_ccb[i].pppoe));
		rte_timer_init(&(ppp_ccb[i].ppp));
		rte_timer_init(&(ppp_ccb[i].nat));
		rte_timer_init(&(ppp_ccb[i].ppp_alive));
		rte_atomic16_init(&ppp_ccb[i].dp_start_bool);
		rte_atomic16_init(&ppp_ccb[i].ppp_bool);
		ppp_ccb[i].ppp_user_id = (unsigned char *)"asdf";
		ppp_ccb[i].ppp_passwd = (unsigned char *)"zxcv";
		ppp_ccb[i].pppoe_phase.pppoe_header_tag = vrg_malloc(pppoe_header_tag_t, RTE_CACHE_LINE_SIZE, RTE_CACHE_LINE_SIZE);
		if (ppp_ccb[i].pppoe_phase.pppoe_header_tag == NULL) {
			VRG_LOG(ERR, vrg_ccb->fp, NULL, PPPLOGMSG, "vrg_malloc failed: %s", rte_strerror(errno));
			return ERROR;
		}
	}
    
	sleep(1);
	VRG_LOG(INFO, vrg_ccb->fp, NULL, PPPLOGMSG, "============ pppoe init successfully ==============\n");
	return SUCCESS;
}

STATUS ppp_connect(PPP_INFO_t *ppp_ccb, U16 user_id)
{
	if (ppp_ccb->phase > END_PHASE) {
		VRG_LOG(ERR, vrg_ccb->fp, ppp_ccb, PPPLOGMSG, "Error! User %u is in a pppoe connection", user_id);
		return ERROR;
	}
	ppp_ccb->phase = PPPOE_PHASE;
	ppp_ccb->pppoe_phase.max_retransmit = MAX_RETRAN;
	ppp_ccb->pppoe_phase.timer_counter = 0;
    if (send_pkt(ENCODE_PADI, ppp_ccb) == ERROR)
		PPP_bye(ppp_ccb);
	/* set ppp starting boolean flag to TRUE */
	rte_atomic16_set(&ppp_ccb->ppp_bool, 1);
	rte_timer_reset(&ppp_ccb->pppoe, rte_get_timer_hz(), PERIODICAL, vrg_ccb->lcore.timer_thread, (rte_timer_cb_t)A_padi_timer_func, ppp_ccb);

	return SUCCESS;
}

STATUS ppp_disconnect(PPP_INFO_t *ppp_ccb, U16 user_id)
{
	if (ppp_ccb->phase == END_PHASE) {
		VRG_LOG(ERR, vrg_ccb->fp, ppp_ccb, PPPLOGMSG, "Error! User %u is in init phase", user_id);
		return ERROR;
	}
	if (ppp_ccb->ppp_processing == TRUE) {
		VRG_LOG(ERR, vrg_ccb->fp, ppp_ccb, PPPLOGMSG, "Error! User %u is disconnecting pppoe connection, please wait...", user_id);
		return ERROR;
	}
	PPP_bye(ppp_ccb);

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
 * @retval SUCCESS if process successfully
 * @retval ERROR if process failed
 */
STATUS ppp_process(void	*mail)
{
	tVRG_MBX			*vrg_mail = (tVRG_MBX *)mail;
	PPP_INFO_t			*ppp_ccb = vrg_ccb->ppp_ccb;
	int 				ret;
	U16					event, user_id = 0;

	ret = get_session_id(vrg_mail, &user_id);
	if (ret == ERROR)
		return ERROR;

	ret = PPP_decode_frame(vrg_mail, &event ,&ppp_ccb[user_id]);
	if (ret == ERROR)					
		return ERROR;
	
	if (check_auth_result(&ppp_ccb[user_id]) == 1) {
		return ERROR;
	}

	ppp_ccb[user_id].ppp_phase[ppp_ccb[user_id].cp].event = event;
	PPP_FSM(&(ppp_ccb[user_id].ppp), &ppp_ccb[user_id], event);
	vrg_mfree(ppp_ccb[user_id].ppp_phase[ppp_ccb[user_id].cp].ppp_options);
	
	return SUCCESS;
}
