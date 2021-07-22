#include <common.h>
#include "dhcp_fsm.h"
#include "dbg.h"
#include "vrg.h"

extern struct lcore_map 	lcore;

extern STATUS build_dhcp_offer(dhcp_ccb_t *dhcp_ccb);
extern STATUS build_dhcp_ack(dhcp_ccb_t *dhcp_ccb);
extern STATUS build_dhcp_nak(dhcp_ccb_t *dhcp_ccb);

STATUS A_create_offer_event(struct rte_timer *tim, dhcp_ccb_t *dhcp_ccb);
STATUS A_send_dhcp_offer(__attribute__((unused)) struct rte_timer *tim, dhcp_ccb_t *dhcp_ccb);
STATUS A_wait_request_timer(struct rte_timer *tim, dhcp_ccb_t *dhcp_ccb);
STATUS A_send_dhcp_ack(struct rte_timer *tim, dhcp_ccb_t *dhcp_ccb);
STATUS A_send_dhcp_nak(struct rte_timer *tim, dhcp_ccb_t *dhcp_ccb);
STATUS A_wait_lease_timer(struct rte_timer *tim, dhcp_ccb_t *dhcp_ccb);
STATUS A_release(struct rte_timer *tim, dhcp_ccb_t *dhcp_ccb);

tDHCP_STATE_TBL  dhcp_fsm_tbl[9] = { 
/*//////////////////////////////////////////////////////////////////////////////////
  	STATE   		EVENT           						      NEXT-STATE            HANDLER       
///////////////////////////////////////////////////////////////////////////////////\*/
{ S_DHCP_INIT,           E_DISCOVER,     						    S_DHCP_OFFER_SENT,		 { A_send_dhcp_offer, A_wait_request_timer, 0 }},

{ S_DHCP_OFFER_SENT,     E_DISCOVER,                                S_DHCP_OFFER_SENT,       { A_send_dhcp_offer, A_wait_request_timer, 0 }},

{ S_DHCP_OFFER_SENT,     E_TIMEOUT,                                 S_DHCP_INIT,             { A_release, 0 }},

{ S_DHCP_OFFER_SENT, 	 E_GOOD_REQUEST,						    S_DHCP_ACK_SENT,         { A_send_dhcp_ack, A_wait_lease_timer, 0 }},

{ S_DHCP_REQUEST_RECV,   E_BAD_REQUEST,                             S_DHCP_NAK_SENT,         { A_send_dhcp_nak, 0 }},

{ S_DHCP_ACK_SENT,       E_TIMEOUT,                                 S_DHCP_INIT,             { A_release, 0 }},

{ S_DHCP_ACK_SENT,       E_RELEASE,                                 S_DHCP_INIT,             { A_release, 0 }},

{ S_DHCP_ACK_SENT,       E_GOOD_REQUEST,                            S_DHCP_ACK_SENT,         { A_send_dhcp_ack, A_wait_lease_timer, 0 }},

{ S_DHCP_INVLD, 0, 0, {0}}

};

/***********************************************************************
 * dhcp_fsm
 *
 * purpose : finite state machine.
 * input   : dhcp_timer - timer
 *			 dhcp_ccb - user connection info.
 *           event -
 * return  : error status
 ***********************************************************************/
STATUS dhcp_fsm(dhcp_ccb_t *dhcp_ccb, U16 event)
{	
    register int  	i,j;
    BOOL			retval;
    char 			str1[30],str2[30];

    /* Find a matched state */
    for(i=0; dhcp_fsm_tbl[i].state!=S_DHCP_INVLD; i++)
        if (dhcp_fsm_tbl[i].state == dhcp_ccb->lan_user_info[dhcp_ccb->cur_lan_user_index].state)
            break;
    DBG_vRG(DBGDHCP,(U8 *)dhcp_ccb,"Current state is %s\n",DHCP_state2str(dhcp_fsm_tbl[i].state));
    if (dhcp_fsm_tbl[i].state == S_DHCP_INVLD) {
        DBG_vRG(DBGDHCP,(U8 *)dhcp_ccb,"Error! unknown state(%d) specified for the event(%d)\n",
        	dhcp_ccb->lan_user_info[dhcp_ccb->cur_lan_user_index].state, event);
        return FALSE;
    }

    /*
     * Find a matched event in a specific state.
     * Note : a state can accept several events.
     */
    for(;dhcp_fsm_tbl[i].state==dhcp_ccb->lan_user_info[dhcp_ccb->cur_lan_user_index].state; i++)
        if (dhcp_fsm_tbl[i].event == event)
            break;
    
    if (dhcp_fsm_tbl[i].state != dhcp_ccb->lan_user_info[dhcp_ccb->cur_lan_user_index].state) { /* search until meet the next state */
        DBG_vRG(DBGDHCP,(U8 *)dhcp_ccb,"error! invalid event(%d) in state(%s)\n",
            event, DHCP_state2str(dhcp_ccb->lan_user_info[dhcp_ccb->cur_lan_user_index].state));
        return FALSE;
    }
    
    /* Correct state found */
    if (dhcp_ccb->lan_user_info[dhcp_ccb->cur_lan_user_index].state != dhcp_fsm_tbl[i].next_state) {
        strcpy(str1,DHCP_state2str(dhcp_ccb->lan_user_info[dhcp_ccb->cur_lan_user_index].state));
        strcpy(str2,DHCP_state2str(dhcp_fsm_tbl[i].next_state));
        DBG_vRG(DBGDHCP,(U8 *)dhcp_ccb,"dhcp state changed from %s to %s\n",str1,str2);
        dhcp_ccb->lan_user_info[dhcp_ccb->cur_lan_user_index].state = dhcp_fsm_tbl[i].next_state;
    }
    
    for(j=0; dhcp_fsm_tbl[i].hdl[j]; j++) {
    	dhcp_ccb->lan_user_info[dhcp_ccb->cur_lan_user_index].timer_counter = 10;
       	retval = (*dhcp_fsm_tbl[i].hdl[j])(&dhcp_ccb->lan_user_info[dhcp_ccb->cur_lan_user_index].timer, dhcp_ccb);
       	if (retval == FALSE)  
            return FALSE;
    }
    return TRUE;
}

STATUS A_send_dhcp_offer(__attribute__((unused)) struct rte_timer *tim, dhcp_ccb_t *dhcp_ccb)
{
    if (build_dhcp_offer(dhcp_ccb) == TRUE)
        return TRUE;
    else 
        return FALSE;
}

void request_timer(struct rte_timer *tim, dhcp_ccb_t *dhcp_ccb)
{
    dhcp_fsm(dhcp_ccb, E_TIMEOUT);
}

STATUS A_wait_request_timer(struct rte_timer *tim, dhcp_ccb_t *dhcp_ccb)
{
    rte_timer_stop(tim);
    rte_timer_reset(tim, 5 * rte_get_timer_hz(), SINGLE, lcore.timer_thread, (rte_timer_cb_t)request_timer, dhcp_ccb);
    return TRUE;
}

STATUS A_send_dhcp_ack(struct rte_timer *tim, dhcp_ccb_t *dhcp_ccb)
{
    if (build_dhcp_ack(dhcp_ccb) == TRUE)
        return TRUE;
    else 
        return FALSE;
}

STATUS A_send_dhcp_nak(struct rte_timer *tim, dhcp_ccb_t *dhcp_ccb)
{
    if (build_dhcp_nak(dhcp_ccb) == TRUE)
        return TRUE;
    else 
        return FALSE;
}

void lease_timer(struct rte_timer *tim, dhcp_ccb_t *dhcp_ccb)
{
    dhcp_fsm(dhcp_ccb, E_TIMEOUT);
}

STATUS A_wait_lease_timer(struct rte_timer *tim, dhcp_ccb_t *dhcp_ccb)
{
    dhcp_ccb_t dhcp_ccb_for_timer = *dhcp_ccb;

    rte_timer_stop(tim);
    rte_timer_reset(tim, LEASE_TIMEOUT * rte_get_timer_hz(), SINGLE, lcore.timer_thread, (rte_timer_cb_t)lease_timer, &dhcp_ccb_for_timer);
    
    return TRUE;
}

STATUS A_release(struct rte_timer *tim, dhcp_ccb_t *dhcp_ccb)
{
    dhcp_ccb->ip_pool[dhcp_ccb->cur_ip_pool_index].used = FALSE;
    return TRUE;
}