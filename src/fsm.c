#include <inttypes.h>
#include <rte_common.h>
#include <rte_memory.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_cycles.h>
#include <rte_timer.h>
#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_flow.h>
#include "fsm.h"
#include "dbg.h"
#include "vrg.h"
#include "nat.h"

extern struct lcore_map 	lcore;
static VRG_t *vrg_ccb;

STATUS 			PPP_FSM(struct rte_timer *ppp, PPP_INFO_t *s_ppp_ccb, U16 event);

static STATUS   A_this_layer_start(__attribute__((unused)) struct rte_timer *tim, __attribute__((unused)) PPP_INFO_t *s_ppp_ccb);
static STATUS   A_send_config_request(__attribute__((unused)) struct rte_timer *tim, __attribute__((unused)) PPP_INFO_t *s_ppp_ccb);
static STATUS   A_this_layer_finish(__attribute__((unused)) struct rte_timer *tim, __attribute__((unused)) PPP_INFO_t *s_ppp_ccb);
static STATUS   A_send_terminate_ack(__attribute__((unused)) struct rte_timer *tim, __attribute__((unused)) PPP_INFO_t *s_ppp_ccb);
static STATUS   A_send_code_reject(__attribute__((unused)) struct rte_timer *tim, __attribute__((unused)) PPP_INFO_t *s_ppp_ccb);
static STATUS   A_create_down_event(__attribute__((unused)) struct rte_timer *tim, __attribute__((unused)) PPP_INFO_t *s_ppp_ccb);
static STATUS   A_create_up_event(__attribute__((unused)) struct rte_timer *tim, __attribute__((unused)) PPP_INFO_t *s_ppp_ccb);
static STATUS   A_send_config_ack(__attribute__((unused)) struct rte_timer *tim, __attribute__((unused)) PPP_INFO_t *s_ppp_ccb);
static STATUS   A_send_config_nak_rej(__attribute__((unused)) struct rte_timer *tim, __attribute__((unused)) PPP_INFO_t *s_ppp_ccb);
static STATUS   A_send_terminate_request(__attribute__((unused)) struct rte_timer *tim, __attribute__((unused)) PPP_INFO_t *s_ppp_ccb);
static STATUS   A_this_layer_up(__attribute__((unused)) struct rte_timer *tim, __attribute__((unused)) PPP_INFO_t *s_ppp_ccb);
static STATUS   A_this_layer_down(__attribute__((unused)) struct rte_timer *tim, __attribute__((unused)) PPP_INFO_t *s_ppp_ccb);
static STATUS   A_init_restart_count(__attribute__((unused)) struct rte_timer *tim, __attribute__((unused)) PPP_INFO_t *s_ppp_ccb);
static STATUS   A_init_restart_config(__attribute__((unused)) struct rte_timer *tim, __attribute__((unused)) PPP_INFO_t *s_ppp_ccb);
static STATUS   A_init_restart_termin(__attribute__((unused)) struct rte_timer *tim, __attribute__((unused)) PPP_INFO_t *s_ppp_ccb);
static STATUS   A_send_echo_reply(__attribute__((unused)) struct rte_timer *tim, __attribute__((unused)) PPP_INFO_t *s_ppp_ccb);
static STATUS   A_zero_restart_count(__attribute__((unused)) struct rte_timer *tim, __attribute__((unused)) PPP_INFO_t *s_ppp_ccb);
static STATUS 	A_send_padt(__attribute__((unused)) struct rte_timer *tim, __attribute__((unused)) PPP_INFO_t *s_ppp_ccb);
static STATUS 	A_create_close_to_lower_layer(__attribute__((unused)) struct rte_timer *tim, __attribute__((unused)) PPP_INFO_t *s_ppp_ccb);

//extern BOOL                     prompt;
//extern struct rte_flow *generate_lan_flow(U16 port_id, U16 rx_q_udp, U16 rx_q_tcp, struct rte_flow_error *error);
//extern struct rte_flow *generate_wan_flow(U16 port_id, U16 rx_q_udp, U16 rx_q_tcp, struct rte_flow_error *error);

tPPP_STATE_TBL  ppp_fsm_tbl[2][122] = { 
/*//////////////////////////////////////////////////////////////////////////////////
  	STATE   		EVENT           						      NEXT-STATE            HANDLER       
///////////////////////////////////////////////////////////////////////////////////\*/
{{ S_INIT,		  	E_UP,     							    	  	S_CLOSED,		    { 0 }},

/* these actions are "this layer start" (tls) and should retern "UP" event */
{ S_INIT,		  	E_OPEN,     						    		S_STARTING,		    { A_this_layer_start, 0 }},

{ S_INIT, 			E_CLOSE,							      		S_INIT, 		    { 0 }},	                                                      	  

/*---------------------------------------------------------------------------*/
{ S_STARTING,		E_UP,     							    		S_REQUEST_SENT,	  	{ A_send_config_request, A_init_restart_config, 0 }},

{ S_STARTING,		E_OPEN,    							    		S_STARTING,		    { 0 }},

/* these actions are "this layer finish" (tlf) and should retern "DOWN" event */
{ S_STARTING,		E_CLOSE,    						    		S_INIT,			    { A_this_layer_finish, A_send_padt, 0 }},

/*---------------------------------------------------------------------------*/
{ S_CLOSED,			E_UP, 							      		    S_CLOSED,			{ 0 }},

{ S_CLOSED,			E_DOWN, 							      		S_INIT,			    { A_send_padt, 0 }},

{ S_CLOSED,			E_OPEN, 							      		S_REQUEST_SENT,	  	{ A_send_config_request, A_init_restart_config, 0 }},

{ S_CLOSED,			E_CLOSE, 							      		S_CLOSED,		    { 0 }},

{ S_CLOSED,			E_RECV_GOOD_CONFIG_REQUEST, 					S_CLOSED,		    { A_send_terminate_ack, 0 }},

{ S_CLOSED,			E_RECV_BAD_CONFIG_REQUEST, 						S_CLOSED,		    { A_send_terminate_ack, 0 }},

{ S_CLOSED,			E_RECV_CONFIG_ACK, 								S_CLOSED,		    { A_send_terminate_ack, 0 }},

{ S_CLOSED,			E_RECV_CONFIG_NAK_REJ, 							S_CLOSED,		    { A_send_terminate_ack, 0 }},

{ S_CLOSED,			E_RECV_TERMINATE_REQUEST, 						S_CLOSED,		    { A_send_terminate_ack, 0 }},

{ S_CLOSED,			E_RECV_TERMINATE_ACK, 							S_CLOSED,		    { 0 }},

{ S_CLOSED,			E_RECV_UNKNOWN_CODE, 							S_CLOSED,		    { A_send_code_reject, 0 }},

/* recv code/protocol reject when rejected value is acceptable, 
	such as a Code-Reject of an extended code, 
	or a Protocol-Reject of a NCP */ 
{ S_CLOSED,			E_RECV_GOOD_CODE_PROTOCOL_REJECT, 				S_CLOSED,	  		{ 0 }},

{ S_CLOSED,			E_RECV_BAD_CODE_PROTOCOL_REJECT, 				S_CLOSED,			{ A_this_layer_finish, 0 }},

{ S_CLOSED,			E_RECV_ECHO_REPLY_REQUEST_DISCARD_REQUEST, 		S_CLOSED,			{ 0 }},

/*---------------------------------------------------------------------------*/
{ S_STOPPED,		E_DOWN,     						   			S_STARTING,		    { A_this_layer_start, 0 }},

{ S_STOPPED,		E_OPEN,     						   			S_STOPPED,		    { A_create_down_event, A_create_up_event, 0 }},

{ S_STOPPED,		E_CLOSE,     						   			S_CLOSED,		    { A_send_padt, 0 }},

{ S_STOPPED,		E_RECV_GOOD_CONFIG_REQUEST,						S_ACK_SENT,		    { A_init_restart_config, A_send_config_request, A_send_config_ack, 0 }},

{ S_STOPPED,		E_RECV_BAD_CONFIG_REQUEST, 						S_REQUEST_SENT,	  	{ A_init_restart_config, A_send_config_request, A_send_config_nak_rej, 0 }},
	
{ S_STOPPED,		E_RECV_CONFIG_ACK, 				 				S_STOPPED,		    { A_send_terminate_ack, 0 }},

{ S_STOPPED,		E_RECV_CONFIG_NAK_REJ, 		 					S_STOPPED,		    { A_send_terminate_ack, 0 }},

{ S_STOPPED,		E_RECV_TERMINATE_REQUEST,  						S_STOPPED,		    { A_send_terminate_ack, 0 }},

{ S_STOPPED,		E_RECV_TERMINATE_ACK, 		 					S_STOPPED,		    { 0 }},
	
{ S_STOPPED,		E_RECV_UNKNOWN_CODE, 			 				S_STOPPED,		    { A_send_code_reject, 0 }},

/* recv code/protocol reject when rejected value is acceptable, 
	such as a Code-Reject of an extended code, 
	or a Protocol-Reject of a NCP */ 
{ S_STOPPED,		E_RECV_GOOD_CODE_PROTOCOL_REJECT, 				S_STOPPED,			{ 0 }},

{ S_STOPPED,		E_RECV_BAD_CODE_PROTOCOL_REJECT, 				S_STOPPED,			{ A_this_layer_finish, 0 }},

{ S_STOPPED,		E_RECV_ECHO_REPLY_REQUEST_DISCARD_REQUEST, 		S_STOPPED,			{ 0 }},

/*---------------------------------------------------------------------------*/
{ S_CLOSING, 		E_DOWN,								     		S_INIT,			    { 0 }},

{ S_CLOSING, 		E_OPEN,								     		S_STOPPING,		    { A_create_down_event, A_create_up_event, 0 }},

{ S_CLOSING, 		E_CLOSE,							     		S_CLOSING,		    { 0 }},

{ S_CLOSING, 		E_TIMEOUT_COUNTER_POSITIVE,						S_CLOSING,		    { A_send_terminate_request, 0 }},

{ S_CLOSING, 		E_TIMEOUT_COUNTER_EXPIRED, 						S_CLOSED,		    { A_this_layer_finish, 0 }},

{ S_CLOSING,		E_RECV_GOOD_CONFIG_REQUEST,						S_CLOSING,		    { 0 }},

{ S_CLOSING,		E_RECV_BAD_CONFIG_REQUEST, 						S_CLOSING,		    { 0 }},

{ S_CLOSING,		E_RECV_CONFIG_ACK, 								S_CLOSING,		    { 0 }},

{ S_CLOSING,		E_RECV_CONFIG_NAK_REJ, 		 					S_CLOSING,		    { 0 }},

{ S_CLOSING,		E_RECV_TERMINATE_REQUEST,  						S_CLOSING,		    { A_send_terminate_ack, 0 }},

{ S_CLOSING,		E_RECV_TERMINATE_ACK, 		 					S_CLOSED,		    { A_create_down_event, A_create_up_event, 0 }},

{ S_CLOSING,		E_RECV_UNKNOWN_CODE, 							S_CLOSING,		    { A_send_code_reject, 0 }},

/* recv code/protocol reject when rejected value is acceptable, 
	such as a Code-Reject of an extended code, 
	or a Protocol-Reject of a NCP */ 
{ S_CLOSING,		E_RECV_GOOD_CODE_PROTOCOL_REJECT, 				S_CLOSING,  		{ 0 }},

{ S_CLOSING,		E_RECV_BAD_CODE_PROTOCOL_REJECT, 				S_CLOSED,			{ A_this_layer_finish, 0 }},

{ S_CLOSING,		E_RECV_ECHO_REPLY_REQUEST_DISCARD_REQUEST, 		S_CLOSING,			{ 0 }},

/*---------------------------------------------------------------------------*/
{ S_STOPPING, 		E_DOWN,								     		S_STARTING, 	    { 0 }},

{ S_STOPPING, 		E_OPEN,								     		S_STOPPING, 	    { A_create_down_event, A_create_up_event, 0 }},

{ S_STOPPING, 		E_CLOSE,							     		S_CLOSING, 		    { 0 }},

{ S_STOPPING, 		E_TIMEOUT_COUNTER_POSITIVE,						S_STOPPING,		    { A_send_terminate_request, 0 }},

{ S_STOPPING, 		E_TIMEOUT_COUNTER_EXPIRED, 						S_STOPPED,		    { A_this_layer_finish, 0 }},

{ S_STOPPING,		E_RECV_GOOD_CONFIG_REQUEST,     				S_STOPPING,			{ 0 }},

{ S_STOPPING,		E_RECV_BAD_CONFIG_REQUEST,     					S_STOPPING,			{ 0 }},

{ S_STOPPING,		E_RECV_CONFIG_ACK, 								S_STOPPING,			{ 0 }},

{ S_STOPPING,		E_RECV_CONFIG_NAK_REJ, 							S_STOPPING,			{ 0 }},

{ S_STOPPING,		E_RECV_TERMINATE_REQUEST, 						S_STOPPING,			{ A_send_terminate_ack, 0 }},

{ S_STOPPING,		E_RECV_TERMINATE_ACK, 							S_STOPPED,			{ A_create_down_event, A_create_up_event, 0 }},

{ S_STOPPING,		E_RECV_UNKNOWN_CODE, 							S_STOPPING,			{ A_send_code_reject, 0 }},

/* recv code/protocol reject when rejected value is acceptable, 
	such as a Code-Reject of an extended code, 
	or a Protocol-Reject of a NCP */ 
{ S_STOPPING,		E_RECV_GOOD_CODE_PROTOCOL_REJECT, 				S_STOPPING,			{ 0 }},

{ S_STOPPING,		E_RECV_BAD_CODE_PROTOCOL_REJECT, 				S_STOPPED,			{ A_this_layer_finish, 0 }},

{ S_STOPPING,		E_RECV_ECHO_REPLY_REQUEST_DISCARD_REQUEST, 		S_STOPPING,			{ 0 }},

/*---------------------------------------------------------------------------*/
{ S_REQUEST_SENT, 	E_DOWN,											S_STARTING, 		{ 0 }},

{ S_REQUEST_SENT, 	E_OPEN,											S_REQUEST_SENT, 	{ 0 }},

{ S_REQUEST_SENT, 	E_CLOSE,										S_CLOSING, 			{ A_init_restart_termin, A_send_terminate_request, 0 }},

{ S_REQUEST_SENT, 	E_TIMEOUT_COUNTER_POSITIVE,						S_REQUEST_SENT, 	{ A_send_config_request, 0 }},

/* may be with "PASSIVE" option, with this option, ppp will not exit but then just wait for a valid LCP packet from peer if there is not received from peer */
{ S_REQUEST_SENT, 	E_TIMEOUT_COUNTER_EXPIRED,						S_STOPPED, 			{ A_this_layer_finish, 0 }},

{ S_REQUEST_SENT, 	E_RECV_GOOD_CONFIG_REQUEST,						S_ACK_SENT,			{ A_send_config_ack, 0 }},

{ S_REQUEST_SENT, 	E_RECV_BAD_CONFIG_REQUEST,						S_REQUEST_SENT,		{ A_send_config_nak_rej, 0 }},

{ S_REQUEST_SENT, 	E_RECV_CONFIG_ACK,								S_ACK_RECEIVED,		{ A_init_restart_count, 0 }},

{ S_REQUEST_SENT, 	E_RECV_CONFIG_NAK_REJ,							S_REQUEST_SENT,		{ A_init_restart_config, A_send_config_request, 0 }},

{ S_REQUEST_SENT, 	E_RECV_TERMINATE_REQUEST,						S_REQUEST_SENT,		{ A_send_terminate_ack, 0 }},

{ S_REQUEST_SENT, 	E_RECV_TERMINATE_ACK,							S_REQUEST_SENT,		{ 0 }},

{ S_REQUEST_SENT, 	E_RECV_UNKNOWN_CODE,							S_REQUEST_SENT,		{ A_send_code_reject, 0 }},

{ S_REQUEST_SENT, 	E_RECV_GOOD_CODE_PROTOCOL_REJECT,				S_REQUEST_SENT,		{ 0 }},

{ S_REQUEST_SENT, 	E_RECV_BAD_CODE_PROTOCOL_REJECT,				S_STOPPED,			{ A_this_layer_finish, 0 }},

{ S_REQUEST_SENT, 	E_RECV_ECHO_REPLY_REQUEST_DISCARD_REQUEST, 		S_REQUEST_SENT,		{ 0 }},

/*---------------------------------------------------------------------------*/
{ S_ACK_RECEIVED, 	E_DOWN,											S_STARTING, 		{ 0 }},

{ S_ACK_RECEIVED, 	E_OPEN,											S_ACK_RECEIVED, 	{ 0 }},

{ S_ACK_RECEIVED, 	E_CLOSE,										S_CLOSING, 			{ A_init_restart_termin, A_send_terminate_request, 0 }},

{ S_ACK_RECEIVED, 	E_TIMEOUT_COUNTER_POSITIVE,						S_REQUEST_SENT, 	{ A_send_config_request, 0 }},

/* may be with "PASSIVE" option, with this option, ppp will not exit but then just wait for a valid LCP packet from peer if there is not received from peer */
{ S_ACK_RECEIVED, 	E_TIMEOUT_COUNTER_EXPIRED,						S_STOPPED, 			{ A_this_layer_finish, 0 }},

{ S_ACK_RECEIVED, 	E_RECV_GOOD_CONFIG_REQUEST,						S_OPENED,			{ A_send_config_ack, A_this_layer_up, 0 }},

{ S_ACK_RECEIVED, 	E_RECV_BAD_CONFIG_REQUEST,						S_ACK_RECEIVED,		{ A_send_config_nak_rej, 0 }},

/* we should silently discard invalid ack/nak/rej packets and not affect transistions of the automaton 
 * so we just send a configure request packet and do nothing 
 * note: in RFC 1661 it rules we whould log this packet because it`s impossible that a correctly formed packet
         will arrive through a coincidentally-timed cross-connection, but we will skip to log in our implementation
 */
{ S_ACK_RECEIVED, 	E_RECV_CONFIG_ACK,								S_REQUEST_SENT,		{ A_send_config_request, 0 }},

{ S_ACK_RECEIVED, 	E_RECV_CONFIG_NAK_REJ,							S_REQUEST_SENT,		{ A_send_config_request, 0 }},

{ S_ACK_RECEIVED, 	E_RECV_TERMINATE_REQUEST,						S_REQUEST_SENT,		{ A_send_terminate_ack, 0 }},

{ S_ACK_RECEIVED, 	E_RECV_TERMINATE_ACK,							S_REQUEST_SENT,		{ 0 }},

{ S_ACK_RECEIVED, 	E_RECV_UNKNOWN_CODE,							S_ACK_RECEIVED,		{ A_send_code_reject, 0 }},

{ S_ACK_RECEIVED, 	E_RECV_GOOD_CODE_PROTOCOL_REJECT,				S_REQUEST_SENT,		{ 0 }},

{ S_ACK_RECEIVED, 	E_RECV_BAD_CODE_PROTOCOL_REJECT,				S_STOPPED,			{ A_this_layer_finish, 0 }},

{ S_ACK_RECEIVED, 	E_RECV_ECHO_REPLY_REQUEST_DISCARD_REQUEST, 		S_ACK_RECEIVED,		{ 0 }},

/*---------------------------------------------------------------------------*/
{ S_ACK_SENT, 		E_DOWN,											S_STARTING, 		{ 0 }},

{ S_ACK_SENT, 		E_OPEN,											S_ACK_SENT, 		{ 0 }},

{ S_ACK_SENT, 		E_CLOSE,										S_CLOSING, 			{ A_init_restart_termin, A_send_terminate_request, 0 }},
	
{ S_ACK_SENT, 		E_TIMEOUT_COUNTER_POSITIVE,						S_ACK_SENT, 		{ A_send_config_request, 0 }},

/* may be with "PASSIVE" option, with this option, ppp will not exit but then just wait for a valid LCP packet from peer if there is not received from peer */
{ S_ACK_SENT, 		E_TIMEOUT_COUNTER_EXPIRED,						S_STOPPED, 			{ A_this_layer_finish, 0 }},

{ S_ACK_SENT, 		E_RECV_GOOD_CONFIG_REQUEST,						S_ACK_SENT,			{ A_send_config_ack, 0 }},

{ S_ACK_SENT, 		E_RECV_BAD_CONFIG_REQUEST,						S_REQUEST_SENT,		{ A_send_config_nak_rej, 0 }},

{ S_ACK_SENT, 		E_RECV_CONFIG_ACK,								S_OPENED,			{ A_init_restart_count, A_this_layer_up, 0 }},

{ S_ACK_SENT, 		E_RECV_CONFIG_NAK_REJ,							S_ACK_SENT,			{ A_init_restart_config, A_send_config_request, 0 }},

{ S_ACK_SENT, 		E_RECV_TERMINATE_REQUEST,						S_REQUEST_SENT,		{ A_send_terminate_ack, 0 }},

{ S_ACK_SENT, 		E_RECV_TERMINATE_ACK,							S_ACK_SENT,			{ 0 }},

{ S_ACK_SENT, 		E_RECV_UNKNOWN_CODE,							S_ACK_SENT,			{ A_send_code_reject, 0 }},

{ S_ACK_SENT, 		E_RECV_GOOD_CODE_PROTOCOL_REJECT,				S_ACK_SENT,			{ 0 }},

{ S_ACK_SENT, 		E_RECV_BAD_CODE_PROTOCOL_REJECT,				S_STOPPED,			{ A_this_layer_finish, 0 }},

{ S_ACK_SENT, 		E_RECV_ECHO_REPLY_REQUEST_DISCARD_REQUEST, 		S_ACK_SENT,			{ 0 }},

/*---------------------------------------------------------------------------*/
{ S_OPENED, 		E_DOWN,											S_STARTING, 		{ A_this_layer_down, 0 }},

{ S_OPENED, 		E_OPEN,											S_OPENED, 			{ A_create_down_event, A_create_up_event, 0 }},

{ S_OPENED, 		E_CLOSE,										S_CLOSING, 			{ A_this_layer_down, A_init_restart_termin, A_send_terminate_request, 0 }},

{ S_OPENED, 		E_RECV_GOOD_CONFIG_REQUEST,						S_ACK_SENT,			{ A_this_layer_down, A_send_config_request, A_send_config_ack, 0 }},

{ S_OPENED, 		E_RECV_BAD_CONFIG_REQUEST,						S_REQUEST_SENT,		{ A_this_layer_down, A_send_config_request, A_send_config_nak_rej, 0 }},

/* we should silently discard invalid ack/nak/rej packets and not affect transistions of the automaton 
 * so we just send a configure request packet and do nothing 
 * note: in RFC 1661 it rules we whould log this packet because it`s impossible that a correctly formed packet
         will arrive through a coincidentally-timed cross-connection, but we will skip to log in our implementation
 */
{ S_OPENED, 		E_RECV_CONFIG_ACK,								S_REQUEST_SENT,		{ A_this_layer_down, A_send_config_request, 0 }},
	
{ S_OPENED, 		E_RECV_CONFIG_NAK_REJ,							S_REQUEST_SENT,		{ A_this_layer_down, A_send_config_request, 0 }},

{ S_OPENED, 		E_RECV_TERMINATE_REQUEST,						S_STOPPING,			{ A_this_layer_down, A_init_restart_termin, A_send_terminate_request, A_send_terminate_ack, 0 }},

{ S_OPENED, 		E_RECV_TERMINATE_ACK,							S_REQUEST_SENT,		{ A_this_layer_down, A_send_config_request, 0 }},

{ S_OPENED, 		E_RECV_UNKNOWN_CODE,							S_OPENED,			{ A_send_code_reject, 0 }},

{ S_OPENED, 		E_RECV_GOOD_CODE_PROTOCOL_REJECT,				S_OPENED,			{ 0 }},

{ S_OPENED, 		E_RECV_BAD_CODE_PROTOCOL_REJECT,				S_STOPPING,			{ A_this_layer_down, A_init_restart_termin, A_send_terminate_request, 0 }},

{ S_OPENED, 		E_RECV_ECHO_REPLY_REQUEST_DISCARD_REQUEST,		S_OPENED,			{ A_send_echo_reply, 0 }},

{ S_INVLD, 0, 0, {0}}},

{{ S_INIT,		  	E_UP,     							    		S_CLOSED,		    { 0 }},

/* these actions are "this layer start" (tls) and should retern "UP" event */
{ S_INIT,		  	E_OPEN,     						    		S_STARTING,		    { A_this_layer_start, 0 }},

{ S_INIT, 			E_CLOSE,							      		S_INIT, 		    { 0 }},	                                                      	  

/*---------------------------------------------------------------------------*/
{ S_STARTING,		E_UP,     							    		S_REQUEST_SENT,	  	{ A_send_config_request, A_init_restart_config, 0 }},

{ S_STARTING,		E_OPEN,    							    		S_STARTING,		    { 0 }},

/* these actions are "this layer finish" (tlf) and should retern "DOWN" event */
{ S_STARTING,		E_CLOSE,    						    		S_INIT,			    { A_this_layer_finish, 0 }},

/*---------------------------------------------------------------------------*/
{ S_CLOSED,			E_DOWN, 							      		S_INIT,			    { A_create_close_to_lower_layer, 0 }},

{ S_CLOSED,			E_OPEN, 							      		S_REQUEST_SENT,	  	{ A_send_config_request, A_init_restart_config, 0 }},

{ S_CLOSED,			E_CLOSE, 							      		S_CLOSED,		    { 0 }},

{ S_CLOSED,			E_RECV_GOOD_CONFIG_REQUEST, 					S_CLOSED,		    { A_send_terminate_ack, 0 }},

{ S_CLOSED,			E_RECV_BAD_CONFIG_REQUEST, 						S_CLOSED,		    { A_send_terminate_ack, 0 }},

{ S_CLOSED,			E_RECV_CONFIG_ACK, 								S_CLOSED,		    { A_send_terminate_ack, 0 }},

{ S_CLOSED,			E_RECV_CONFIG_NAK_REJ, 							S_CLOSED,		    { A_send_terminate_ack, 0 }},

{ S_CLOSED,			E_RECV_TERMINATE_REQUEST, 						S_CLOSED,		    { A_send_terminate_ack, 0 }},

{ S_CLOSED,			E_RECV_TERMINATE_ACK, 							S_CLOSED,		    { 0 }},

{ S_CLOSED,			E_RECV_UNKNOWN_CODE, 							S_CLOSED,		    { A_send_code_reject, 0 }},

/* recv code/protocol reject when rejected value is acceptable, 
	such as a Code-Reject of an extended code, 
	or a Protocol-Reject of a NCP */ 
{ S_CLOSED,			E_RECV_GOOD_CODE_PROTOCOL_REJECT, 				S_CLOSED,	  		{ 0 }},

{ S_CLOSED,			E_RECV_BAD_CODE_PROTOCOL_REJECT, 				S_CLOSED,			{ A_this_layer_finish, 0 }},

{ S_CLOSED,			E_RECV_ECHO_REPLY_REQUEST_DISCARD_REQUEST, 		S_CLOSED,			{ 0 }},

/*---------------------------------------------------------------------------*/
{ S_STOPPED,		E_DOWN,     						   			S_STARTING,		    { A_this_layer_start, 0 }},

{ S_STOPPED,		E_OPEN,     						   			S_STOPPED,		    { A_create_down_event, A_create_up_event, 0 }},

{ S_STOPPED,		E_CLOSE,     						   			S_CLOSED,		    { 0 }},

{ S_STOPPED,		E_RECV_GOOD_CONFIG_REQUEST,						S_ACK_SENT,		    { A_init_restart_config, A_send_config_request, A_send_config_ack, 0 }},

{ S_STOPPED,		E_RECV_BAD_CONFIG_REQUEST, 						S_REQUEST_SENT,	  	{ A_init_restart_config, A_send_config_request, A_send_config_nak_rej, 0 }},

{ S_STOPPED,		E_RECV_CONFIG_ACK, 				 				S_STOPPED,		    { A_send_terminate_ack, 0 }},

{ S_STOPPED,		E_RECV_CONFIG_NAK_REJ, 		 					S_STOPPED,		    { A_send_terminate_ack, 0 }},

{ S_STOPPED,		E_RECV_TERMINATE_REQUEST,  						S_STOPPED,		    { A_send_terminate_ack, 0 }},

{ S_STOPPED,		E_RECV_TERMINATE_ACK, 		 					S_STOPPED,		    { 0 }},

{ S_STOPPED,		E_RECV_UNKNOWN_CODE, 			 				S_STOPPED,		    { A_send_code_reject, 0 }},

/* recv code/protocol reject when rejected value is acceptable, 
	such as a Code-Reject of an extended code, 
	or a Protocol-Reject of a NCP */ 
{ S_STOPPED,		E_RECV_GOOD_CODE_PROTOCOL_REJECT, 				S_STOPPED,			{ 0 }},

{ S_STOPPED,		E_RECV_BAD_CODE_PROTOCOL_REJECT, 				S_STOPPED,			{ A_this_layer_finish, 0 }},

{ S_STOPPED,		E_RECV_ECHO_REPLY_REQUEST_DISCARD_REQUEST, 		S_STOPPED,			{ 0 }},

/*---------------------------------------------------------------------------*/
{ S_CLOSING, 		E_DOWN,								     		S_INIT,			    { 0 }},

{ S_CLOSING, 		E_OPEN,								     		S_STOPPING,		    { A_create_down_event, A_create_up_event, 0 }},

{ S_CLOSING, 		E_CLOSE,							     		S_CLOSING,		    { 0 }},

{ S_CLOSING, 		E_TIMEOUT_COUNTER_POSITIVE,						S_CLOSING,		    { A_send_terminate_request, 0 }},

{ S_CLOSING, 		E_TIMEOUT_COUNTER_EXPIRED, 						S_CLOSED,		    { A_this_layer_finish, 0 }},

{ S_CLOSING,		E_RECV_GOOD_CONFIG_REQUEST,						S_CLOSING,		    { 0 }},

{ S_CLOSING,		E_RECV_BAD_CONFIG_REQUEST, 						S_CLOSING,		    { 0 }},

{ S_CLOSING,		E_RECV_CONFIG_ACK, 				 				S_CLOSING,		    { 0 }},

{ S_CLOSING,		E_RECV_CONFIG_NAK_REJ, 		 					S_CLOSING,		    { 0 }},

{ S_CLOSING,		E_RECV_TERMINATE_REQUEST,  						S_CLOSING,		    { A_send_terminate_ack, 0 }},

{ S_CLOSING,		E_RECV_TERMINATE_ACK, 		 					S_CLOSED,		    { A_create_down_event, A_create_up_event, 0 }},

{ S_CLOSING,		E_RECV_UNKNOWN_CODE, 			 				S_CLOSING,		    { A_send_code_reject, 0 }},

/* recv code/protocol reject when rejected value is acceptable, 
	such as a Code-Reject of an extended code, 
	or a Protocol-Reject of a NCP */ 
{ S_CLOSING,		E_RECV_GOOD_CODE_PROTOCOL_REJECT, 				S_CLOSING,  		{ 0 }},

{ S_CLOSING,		E_RECV_BAD_CODE_PROTOCOL_REJECT, 				S_CLOSED,			{ A_this_layer_finish, 0 }},

{ S_CLOSING,		E_RECV_ECHO_REPLY_REQUEST_DISCARD_REQUEST, 		S_CLOSING,			{ 0 }},

/*---------------------------------------------------------------------------*/
{ S_STOPPING, 		E_DOWN,								     		S_STARTING, 	    { 0 }},

{ S_STOPPING, 		E_OPEN,								     		S_STOPPING, 	    { A_create_down_event, A_create_up_event, 0 }},

{ S_STOPPING, 		E_CLOSE,							     		S_CLOSING, 		    { 0 }},

{ S_STOPPING, 		E_TIMEOUT_COUNTER_POSITIVE,						S_STOPPING,		    { A_send_terminate_request, 0 }},

{ S_STOPPING, 		E_TIMEOUT_COUNTER_EXPIRED, 						S_STOPPED,		    { A_this_layer_finish, 0 }},

{ S_STOPPING,		E_RECV_GOOD_CONFIG_REQUEST,     				S_STOPPING,			{ 0 }},

{ S_STOPPING,		E_RECV_BAD_CONFIG_REQUEST,     					S_STOPPING,			{ 0 }},

{ S_STOPPING,		E_RECV_CONFIG_ACK, 								S_STOPPING,			{ 0 }},

{ S_STOPPING,		E_RECV_CONFIG_NAK_REJ, 							S_STOPPING,			{ 0 }},

{ S_STOPPING,		E_RECV_TERMINATE_REQUEST, 						S_STOPPING,			{ A_send_terminate_ack, 0 }},

{ S_STOPPING,		E_RECV_TERMINATE_ACK, 							S_STOPPED,			{ A_create_down_event, A_create_up_event, 0 }},

{ S_STOPPING,		E_RECV_UNKNOWN_CODE, 							S_STOPPING,			{ A_send_code_reject, 0 }},

/* recv code/protocol reject when rejected value is acceptable, 
	such as a Code-Reject of an extended code, 
	or a Protocol-Reject of a NCP */ 
{ S_STOPPING,		E_RECV_GOOD_CODE_PROTOCOL_REJECT, 				S_STOPPING,			{ 0 }},

{ S_STOPPING,		E_RECV_BAD_CODE_PROTOCOL_REJECT, 				S_STOPPED,			{ A_this_layer_finish, 0 }},

{ S_STOPPING,		E_RECV_ECHO_REPLY_REQUEST_DISCARD_REQUEST, 		S_STOPPING,			{ 0 }},

/*---------------------------------------------------------------------------*/
{ S_REQUEST_SENT, 	E_DOWN,											S_STARTING, 		{ 0 }},

{ S_REQUEST_SENT, 	E_OPEN,											S_REQUEST_SENT, 	{ 0 }},

{ S_REQUEST_SENT,	E_CLOSE,										S_CLOSING, 			{ A_init_restart_termin, A_send_terminate_request, 0 }},

{ S_REQUEST_SENT, 	E_TIMEOUT_COUNTER_POSITIVE,						S_REQUEST_SENT, 	{ A_send_config_request, 0 }},

/* may be with "PASSIVE" option, with this option, ppp will not exit but then just wait for a valid LCP packet from peer if there is not received form peer */
{ S_REQUEST_SENT,   E_TIMEOUT_COUNTER_EXPIRED,		                S_STOPPED, 		    { A_this_layer_finish, 0 }},

{ S_REQUEST_SENT,   E_RECV_GOOD_CONFIG_REQUEST,		                S_ACK_SENT,		    { A_send_config_ack, 0 }},

{ S_REQUEST_SENT,   E_RECV_BAD_CONFIG_REQUEST,		                S_REQUEST_SENT,	    { A_send_config_nak_rej, 0 }},

{ S_REQUEST_SENT,   E_RECV_CONFIG_ACK,				                S_ACK_RECEIVED,	    { A_init_restart_count, 0 }},

{ S_REQUEST_SENT,   E_RECV_CONFIG_NAK_REJ,			                S_REQUEST_SENT,	    { A_init_restart_config, A_send_config_request, 0 }},

{ S_REQUEST_SENT,   E_RECV_TERMINATE_REQUEST,			            S_REQUEST_SENT,	    { A_send_terminate_ack, 0 }},

{ S_REQUEST_SENT,   E_RECV_TERMINATE_ACK,				            S_REQUEST_SENT,	    { 0 }},

{ S_REQUEST_SENT,   E_RECV_UNKNOWN_CODE,				            S_REQUEST_SENT,	    { A_send_code_reject, 0 }},

{ S_REQUEST_SENT,   E_RECV_GOOD_CODE_PROTOCOL_REJECT,	            S_REQUEST_SENT,	    { 0 }},

{ S_REQUEST_SENT,   E_RECV_BAD_CODE_PROTOCOL_REJECT,	            S_STOPPED,		    { A_this_layer_finish, 0 }},

{ S_REQUEST_SENT,   E_RECV_ECHO_REPLY_REQUEST_DISCARD_REQUEST,      S_REQUEST_SENT,	    { 0 }},

/*---------------------------------------------------------------------------*/
{ S_ACK_RECEIVED,   E_DOWN,							                S_STARTING, 	    { 0 }},

{ S_ACK_RECEIVED,   E_OPEN,							                S_ACK_RECEIVED,     { 0 }},

{ S_ACK_RECEIVED,   E_CLOSE,							            S_CLOSING, 		    { A_init_restart_termin, A_send_terminate_request, 0 }},

{ S_ACK_RECEIVED,   E_TIMEOUT_COUNTER_POSITIVE,		                S_REQUEST_SENT,     { A_send_config_request, 0 }},

/* may be with "PASSIVE" option, with this option, ppp will not exit but then just wait for a valid LCP packet from peer if there is not received form peer */
{ S_ACK_RECEIVED,   E_TIMEOUT_COUNTER_EXPIRED,		                S_STOPPED, 		    { A_this_layer_finish, 0 }},

{ S_ACK_RECEIVED,   E_RECV_GOOD_CONFIG_REQUEST,		                S_OPENED,		    { A_send_config_ack, A_this_layer_up, 0 }},

{ S_ACK_RECEIVED,   E_RECV_BAD_CONFIG_REQUEST,		                S_ACK_RECEIVED,	    { A_send_config_nak_rej, 0 }},

/* we should silently discard invalid ack/nak/rej packets and not affect transistions of the automaton 
 * so we just send a configure request packet and do nothing 
 * note: in RFC 1661 it rules we whould log this packet because it`s impossible that a correctly formed packet
         will arrive through a coincidentally-timed cross-connection, but we will skip to log in our implementation
 */
{ S_ACK_RECEIVED,   E_RECV_CONFIG_ACK,				                S_REQUEST_SENT,	    { A_send_config_request, 0 }},

{ S_ACK_RECEIVED,   E_RECV_CONFIG_NAK_REJ,			                S_REQUEST_SENT,	    { A_send_config_request, 0 }},

{ S_ACK_RECEIVED,   E_RECV_TERMINATE_REQUEST,			            S_REQUEST_SENT,	    { A_send_terminate_ack, 0 }},

{ S_ACK_RECEIVED,   E_RECV_TERMINATE_ACK,				            S_REQUEST_SENT,	    { 0 }},

{ S_ACK_RECEIVED,   E_RECV_UNKNOWN_CODE,				            S_ACK_RECEIVED,	    { A_send_code_reject, 0 }},

{ S_ACK_RECEIVED,   E_RECV_GOOD_CODE_PROTOCOL_REJECT,	            S_REQUEST_SENT,	    { 0 }},

{ S_ACK_RECEIVED,   E_RECV_BAD_CODE_PROTOCOL_REJECT,	            S_STOPPED,		    { A_this_layer_finish, 0 }},

{ S_ACK_RECEIVED,   E_RECV_ECHO_REPLY_REQUEST_DISCARD_REQUEST,      S_ACK_RECEIVED,	    { 0 }},

/*---------------------------------------------------------------------------*/
{ S_ACK_SENT, 	    E_DOWN,								            S_STARTING, 	    { 0 }},

{ S_ACK_SENT, 	    E_OPEN,								            S_ACK_SENT, 	    { 0 }},

{ S_ACK_SENT, 	    E_CLOSE,							            S_CLOSING, 		    { A_init_restart_termin, A_send_terminate_request, 0 }},
	
{ S_ACK_SENT, 	    E_TIMEOUT_COUNTER_POSITIVE,			            S_ACK_SENT, 	    { A_send_config_request, 0 }},

/* may be with "PASSIVE" option, with this option, ppp will not exit but then just wait for a valid LCP packet from peer if there is not received form peer */
{ S_ACK_SENT, 	    E_TIMEOUT_COUNTER_EXPIRED,			            S_STOPPED, 		    { A_this_layer_finish, 0 }},

{ S_ACK_SENT, 	    E_RECV_GOOD_CONFIG_REQUEST,			            S_ACK_SENT,		    { A_send_config_ack, 0 }},

{ S_ACK_SENT, 	    E_RECV_BAD_CONFIG_REQUEST,			            S_REQUEST_SENT,	    { A_send_config_nak_rej, 0 }},

{ S_ACK_SENT, 	    E_RECV_CONFIG_ACK,					            S_OPENED,		    { A_init_restart_count, A_this_layer_up, 0 }},

{ S_ACK_SENT, 	    E_RECV_CONFIG_NAK_REJ,				            S_ACK_SENT,		    { A_init_restart_config, A_send_config_request, 0 }},

{ S_ACK_SENT, 	    E_RECV_TERMINATE_REQUEST,			            S_REQUEST_SENT,	    { A_send_terminate_ack, 0 }},

{ S_ACK_SENT, 	    E_RECV_TERMINATE_ACK,				            S_ACK_SENT,		    { 0 }},

{ S_ACK_SENT, 	    E_RECV_UNKNOWN_CODE,				            S_ACK_SENT,		    { A_send_code_reject, 0 }},

{ S_ACK_SENT, 	    E_RECV_GOOD_CODE_PROTOCOL_REJECT,	            S_ACK_SENT,		    { 0 }},

{ S_ACK_SENT, 	    E_RECV_BAD_CODE_PROTOCOL_REJECT,	            S_STOPPED,		    { A_this_layer_finish, 0 }},

{ S_ACK_SENT, 	    E_RECV_ECHO_REPLY_REQUEST_DISCARD_REQUEST,      S_ACK_SENT,	        { 0 }},

/*---------------------------------------------------------------------------*/
{ S_OPENED, 	    E_DOWN,								            S_STARTING, 	    { A_this_layer_down, 0 }},

{ S_OPENED, 	    E_OPEN,								            S_OPENED, 		    { A_create_down_event, A_create_up_event, 0 }},

{ S_OPENED, 	    E_CLOSE,							            S_CLOSING, 		    { A_this_layer_down, A_init_restart_termin, A_send_terminate_request, 0 }},

{ S_OPENED, 	    E_RECV_GOOD_CONFIG_REQUEST,			            S_ACK_SENT,		    { A_this_layer_down, A_send_config_request, A_send_config_ack, 0 }},

{ S_OPENED, 	    E_RECV_BAD_CONFIG_REQUEST,			            S_REQUEST_SENT,	    { A_this_layer_down, A_send_config_request, A_send_config_nak_rej, 0 }},

/* we should silently discard invalid ack/nak/rej packets and not affect transistions of the automaton 
 * so we just send a configure request packet and do nothing 
 * note: in RFC 1661 it rules we whould log this packet because it`s impossible that a correctly formed packet
         will arrive through a coincidentally-timed cross-connection, but we will skip to log in our implementation
 */
{ S_OPENED, 	    E_RECV_CONFIG_ACK,					            S_REQUEST_SENT,	    { A_this_layer_down, A_send_config_request, 0 }},
	
{ S_OPENED, 	    E_RECV_CONFIG_NAK_REJ,				            S_REQUEST_SENT,	    { A_this_layer_down, A_send_config_request, 0 }},

{ S_OPENED, 	    E_RECV_TERMINATE_REQUEST,			            S_STOPPING,		    { A_this_layer_down, A_zero_restart_count, A_send_terminate_ack, 0 }},

{ S_OPENED, 	    E_RECV_TERMINATE_ACK,				            S_REQUEST_SENT,	    { A_this_layer_down, A_send_config_request, 0 }},

{ S_OPENED, 	    E_RECV_UNKNOWN_CODE,				            S_OPENED,		    { A_send_code_reject, 0 }},

{ S_OPENED, 	    E_RECV_GOOD_CODE_PROTOCOL_REJECT,	            S_OPENED,		    { 0 }},

{ S_OPENED, 	    E_RECV_BAD_CODE_PROTOCOL_REJECT,	            S_STOPPING,		    { A_this_layer_down, A_init_restart_termin, A_send_terminate_request, 0 }},

{ S_OPENED, 	    E_RECV_ECHO_REPLY_REQUEST_DISCARD_REQUEST,      S_OPENED,           { A_send_echo_reply, 0 }},

{ S_INVLD, 0, 0, {0}}}
};

/***********************************************************************
 * PPP_FSM
 *
 * purpose : finite state machine.
 * input   : ppp - timer
 *			 s_ppp_ccb - user connection info.
 *           event -
 * return  : error status
 ***********************************************************************/
STATUS PPP_FSM(struct rte_timer *ppp, PPP_INFO_t *s_ppp_ccb, U16 event)
{	
    register int  	i,j;
    int			    retval;
    char 			str1[30],str2[30];

    if (!s_ppp_ccb) {
        VRG_LOG(ERR, vrg_ccb->fp, (U8 *)s_ppp_ccb, PPPLOGMSG, "Error! No port found for the event(%d)",event);
        return FALSE;
    }
    
    /* Find a matched state */
    for(i=0; ppp_fsm_tbl[s_ppp_ccb->cp][i].state!=S_INVLD; i++)
        if (ppp_fsm_tbl[s_ppp_ccb->cp][i].state == s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].state)
            break;

    VRG_LOG(DBG, vrg_ccb->fp, (U8 *)s_ppp_ccb, PPPLOGMSG, "Current state is %s\n", PPP_state2str(ppp_fsm_tbl[s_ppp_ccb->cp][i].state));

    if (ppp_fsm_tbl[s_ppp_ccb->cp][i].state == S_INVLD) {
        VRG_LOG(ERR, vrg_ccb->fp, (U8 *)s_ppp_ccb, PPPLOGMSG, "Error! user %" PRIu16 " unknown state(%d) specified for the event(%d)",
        	s_ppp_ccb->user_num, s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].state,event);
        return FALSE;
    }

    /*
     * Find a matched event in a specific state.
     * Note : a state can accept several events.
     */
    for(;ppp_fsm_tbl[s_ppp_ccb->cp][i].state==s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].state; i++)
        if (ppp_fsm_tbl[s_ppp_ccb->cp][i].event == event)
            break;
    
    if (ppp_fsm_tbl[s_ppp_ccb->cp][i].state != s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].state) { /* search until meet the next state */
        VRG_LOG(INFO, vrg_ccb->fp, (U8 *)s_ppp_ccb, PPPLOGMSG, "Error! user %" PRIu16 " invalid event(%d) in state(%s)",
            s_ppp_ccb->user_num, event, PPP_state2str(s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].state));
  		return TRUE; /* still pass to endpoint */
    }
    
    /* Correct state found */
    if (s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].state != ppp_fsm_tbl[s_ppp_ccb->cp][i].next_state) {
        strcpy(str1,PPP_state2str(s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].state));
        strcpy(str2,PPP_state2str(ppp_fsm_tbl[s_ppp_ccb->cp][i].next_state));
        VRG_LOG(DBG, vrg_ccb->fp, (U8 *)s_ppp_ccb, PPPLOGMSG,"User %" PRIu16 " %s state changed from %s to %s.", s_ppp_ccb->user_num, (s_ppp_ccb->cp == 1 ? "IPCP" : "LCP"), str1, str2);
        s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].state = ppp_fsm_tbl[s_ppp_ccb->cp][i].next_state;
    }
    
    for(j=0; ppp_fsm_tbl[s_ppp_ccb->cp][i].hdl[j]; j++) {
    	s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].timer_counter = 10;
       	retval = (*ppp_fsm_tbl[s_ppp_ccb->cp][i].hdl[j])(ppp,s_ppp_ccb);
       	if (!retval)  
            return TRUE;
    }
    return TRUE;
}

/* this layer up/down/start/finish */
STATUS A_this_layer_start(__attribute__((unused)) struct rte_timer *tim, __attribute__((unused)) PPP_INFO_t *s_ppp_ccb)
{
    PPP_FSM(tim,s_ppp_ccb,E_UP);

    return TRUE;
}

STATUS A_this_layer_finish(__attribute__((unused)) struct rte_timer *tim, __attribute__((unused)) PPP_INFO_t *s_ppp_ccb)
{
    PPP_FSM(tim,s_ppp_ccb,E_DOWN);

    return TRUE;
}

STATUS A_this_layer_up(__attribute__((unused)) struct rte_timer *tim, __attribute__((unused)) PPP_INFO_t *s_ppp_ccb)
{
	unsigned char buffer[MSG_BUF];
    U16 mulen;

	if (s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].ppp_payload->ppp_protocol == rte_cpu_to_be_16(LCP_PROTOCOL)) {
    	memset(buffer,0,MSG_BUF);
        rte_timer_reset(&(s_ppp_ccb->ppp_alive), ppp_interval*rte_get_timer_hz(), SINGLE, lcore.timer_thread, (rte_timer_cb_t)exit_ppp, s_ppp_ccb);
    	if (s_ppp_ccb->auth_method == PAP_PROTOCOL) {
            if (build_auth_request_pap(buffer,s_ppp_ccb,&mulen) < 0)
    		    return FALSE;
        }
    	drv_xmit(vrg_ccb, buffer, mulen);
        VRG_LOG(INFO, vrg_ccb->fp, s_ppp_ccb, PPPLOGMSG, "User %" PRIu16 " LCP connection establish successfully.", s_ppp_ccb->user_num);
        VRG_LOG(INFO, vrg_ccb->fp, s_ppp_ccb, PPPLOGMSG, "User %" PRIu16 " starting Authentication.", s_ppp_ccb->user_num);
    }
    else if (s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].ppp_payload->ppp_protocol == rte_cpu_to_be_16(IPCP_PROTOCOL)) {
    	rte_atomic16_set(&s_ppp_ccb->dp_start_bool, (BIT16)1);
        s_ppp_ccb->phase = DATA_PHASE;
    	rte_timer_reset(&(s_ppp_ccb->nat),rte_get_timer_hz(),PERIODICAL,lcore.timer_thread,(rte_timer_cb_t)nat_rule_timer,s_ppp_ccb);
        VRG_LOG(INFO, vrg_ccb->fp, s_ppp_ccb, PPPLOGMSG, "User %" PRIu16 " IPCP connection establish successfully.", s_ppp_ccb->user_num);
        if (unlikely(vrg_ccb->non_vlan_mode == TRUE))
            VRG_LOG(INFO, vrg_ccb->fp, s_ppp_ccb, PPPLOGMSG, "Now user %" PRIu16 " can start to send data via pppoe session id 0x%x.", s_ppp_ccb->user_num, rte_cpu_to_be_16(s_ppp_ccb->session_id));
        else
            VRG_LOG(INFO, vrg_ccb->fp, s_ppp_ccb, PPPLOGMSG, "Now user %" PRIu16 " can start to send data via pppoe session id 0x%x and vlan is %" PRIu16 ".", s_ppp_ccb->user_num, rte_cpu_to_be_16(s_ppp_ccb->session_id), s_ppp_ccb->vlan);
        VRG_LOG(INFO, vrg_ccb->fp, s_ppp_ccb, PPPLOGMSG, "User %" PRIu16 " PPPoE client IP address is %" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8 ", PPPoE server IP address is %" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8 , s_ppp_ccb->user_num, *(((U8 *)&(s_ppp_ccb->hsi_ipv4))), *(((U8 *)&(s_ppp_ccb->hsi_ipv4))+1), *(((U8 *)&(s_ppp_ccb->hsi_ipv4))+2), *(((U8 *)&(s_ppp_ccb->hsi_ipv4))+3), *(((U8 *)&(s_ppp_ccb->hsi_ipv4_gw))), *(((U8 *)&(s_ppp_ccb->hsi_ipv4_gw))+1), *(((U8 *)&(s_ppp_ccb->hsi_ipv4_gw))+2), *(((U8 *)&(s_ppp_ccb->hsi_ipv4_gw))+3));
        if (unlikely(vrg_ccb->non_vlan_mode == TRUE))
            VRG_LOG(INFO, vrg_ccb->fp, NULL, PPPLOGMSG, "Now user %" PRIu16 " can start to send data via pppoe session id 0x%x.", s_ppp_ccb->user_num, rte_cpu_to_be_16(s_ppp_ccb->session_id));
    	else
            VRG_LOG(INFO, vrg_ccb->fp, NULL, PPPLOGMSG, "Now user %" PRIu16 " can start to send data via pppoe session id 0x%x and vlan is %" PRIu16 ".\n", s_ppp_ccb->user_num, rte_cpu_to_be_16(s_ppp_ccb->session_id), s_ppp_ccb->vlan);
        VRG_LOG(INFO, vrg_ccb->fp, NULL, PPPLOGMSG, "User %" PRIu16 " PPPoE client IP address is %" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8 ", PPPoE server IP address is %" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8 "\n", s_ppp_ccb->user_num, *(((U8 *)&(s_ppp_ccb->hsi_ipv4))), *(((U8 *)&(s_ppp_ccb->hsi_ipv4))+1), *(((U8 *)&(s_ppp_ccb->hsi_ipv4))+2), *(((U8 *)&(s_ppp_ccb->hsi_ipv4))+3), *(((U8 *)&(s_ppp_ccb->hsi_ipv4_gw))), *(((U8 *)&(s_ppp_ccb->hsi_ipv4_gw))+1), *(((U8 *)&(s_ppp_ccb->hsi_ipv4_gw))+2), *(((U8 *)&(s_ppp_ccb->hsi_ipv4_gw))+3));
    }

    return TRUE;
}

/***********************************************************************
 * A_this_layer_down
 *
 * purpose : To notify upper layer this layer is leaving OPEN state.
 * input   : ppp - timer
 *			 s_ppp_ccb - user connection info.
 *           event -
 * return  : error status
 ***********************************************************************/
STATUS A_this_layer_down(__attribute__((unused)) struct rte_timer *tim, __attribute__((unused)) PPP_INFO_t *s_ppp_ccb)
{
    if (s_ppp_ccb->cp == 1) {
        VRG_LOG(DBG, vrg_ccb->fp, s_ppp_ccb, PPPLOGMSG, "IPCP layer is down");
        PPP_FSM(tim,s_ppp_ccb,E_CLOSE);
        rte_atomic16_set(&s_ppp_ccb->dp_start_bool, (BIT16)0);
    }
    else if (s_ppp_ccb->cp == 0) {
        PPP_FSM(tim,s_ppp_ccb,E_CLOSE);
        VRG_LOG(DBG, vrg_ccb->fp, s_ppp_ccb, PPPLOGMSG, "LCP layer is down");
    }

    return TRUE;
}

STATUS A_init_restart_count(__attribute__((unused)) struct rte_timer *tim, __attribute__((unused)) PPP_INFO_t *s_ppp_ccb)
{
    VRG_LOG(DBG, vrg_ccb->fp, s_ppp_ccb, PPPLOGMSG, "init restart count");

    return TRUE;
}

STATUS A_init_restart_config(__attribute__((unused)) struct rte_timer *tim, __attribute__((unused)) PPP_INFO_t *s_ppp_ccb)
{
    VRG_LOG(INFO, vrg_ccb->fp, s_ppp_ccb, PPPLOGMSG, "User %" PRIu16 " init config req timer start.\n", s_ppp_ccb->user_num);
    rte_timer_stop(tim);
    s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].timer_counter = 9;
	rte_timer_reset(tim,3*rte_get_timer_hz(),PERIODICAL,lcore.timer_thread,(rte_timer_cb_t)A_send_config_request,s_ppp_ccb);

    return TRUE;
}

STATUS A_init_restart_termin(__attribute__((unused)) struct rte_timer *tim, __attribute__((unused)) PPP_INFO_t *s_ppp_ccb)
{
    VRG_LOG(DBG, vrg_ccb->fp, s_ppp_ccb, PPPLOGMSG, "User %" PRIu16 " init termin req timer start.\n", s_ppp_ccb->user_num);
    rte_timer_stop(tim);
    s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].timer_counter = 9;
	rte_timer_reset(tim,3*rte_get_timer_hz(),PERIODICAL,lcore.timer_thread,(rte_timer_cb_t)A_send_terminate_request,s_ppp_ccb);

    return TRUE;
}

STATUS A_send_config_request(__attribute__((unused)) struct rte_timer *tim, __attribute__((unused)) PPP_INFO_t *s_ppp_ccb)
{
    unsigned char buffer[MSG_BUF];
    U16 mulen;

    if (s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].timer_counter == 0) {
    	rte_timer_stop(tim);
        VRG_LOG(DBG, vrg_ccb->fp, s_ppp_ccb, PPPLOGMSG, "User %" PRIu16 " config request timeout.\n", s_ppp_ccb->user_num);
    	PPP_FSM(tim,s_ppp_ccb,E_TIMEOUT_COUNTER_EXPIRED);
    }
    if (build_config_request(buffer,s_ppp_ccb,&mulen) < 0)
        return FALSE;
    drv_xmit(vrg_ccb, buffer, mulen);
    s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].timer_counter--;
    
    return TRUE;
}

STATUS A_send_config_nak_rej(__attribute__((unused)) struct rte_timer *tim, __attribute__((unused)) PPP_INFO_t *s_ppp_ccb)
{
    unsigned char buffer[MSG_BUF];
    U16 mulen;

    if (build_config_nak_rej(buffer,s_ppp_ccb,&mulen) < 0)
        return FALSE;
    drv_xmit(vrg_ccb, buffer, mulen);

    return TRUE;
}

STATUS A_send_config_ack(__attribute__((unused)) struct rte_timer *tim, __attribute__((unused)) PPP_INFO_t *s_ppp_ccb)
{
    unsigned char buffer[MSG_BUF];
    U16 mulen;

    if (build_config_ack(buffer,s_ppp_ccb,&mulen) < 0)
        return FALSE;
    drv_xmit(vrg_ccb, buffer, mulen);

    return TRUE;
}

STATUS A_send_terminate_request(__attribute__((unused)) struct rte_timer *tim, __attribute__((unused)) PPP_INFO_t *s_ppp_ccb)
{
    unsigned char buffer[MSG_BUF];
    U16 mulen;

    if (s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].timer_counter == 0) {
    	rte_timer_stop(tim);
        VRG_LOG(DBG, vrg_ccb->fp, s_ppp_ccb, PPPLOGMSG, "User %" PRIu16 " terminate request timeout.\n", s_ppp_ccb->user_num);
    	PPP_FSM(tim,s_ppp_ccb,E_TIMEOUT_COUNTER_EXPIRED);
    }
    if (build_terminate_request(buffer,s_ppp_ccb,&mulen) < 0)
        return FALSE;
    drv_xmit(vrg_ccb, buffer, mulen);
    s_ppp_ccb->ppp_phase[s_ppp_ccb->cp].timer_counter--;
    
    return TRUE;
}

STATUS A_send_terminate_ack(__attribute__((unused)) struct rte_timer *tim, __attribute__((unused)) PPP_INFO_t *s_ppp_ccb)
{
    unsigned char buffer[MSG_BUF];
    U16 mulen;

    if (build_terminate_ack(buffer,s_ppp_ccb,&mulen) < 0)
        return FALSE;
    drv_xmit(vrg_ccb, buffer, mulen);

    return TRUE;
}

STATUS A_send_code_reject(__attribute__((unused)) struct rte_timer *tim, __attribute__((unused)) PPP_INFO_t *s_ppp_ccb)
{
    unsigned char buffer[MSG_BUF];
    U16 mulen;

    if (build_code_reject(buffer,s_ppp_ccb,&mulen) < 0)
        return FALSE;
    drv_xmit(vrg_ccb, buffer, mulen);

    return TRUE;
}

STATUS A_send_echo_reply(__attribute__((unused)) struct rte_timer *tim, __attribute__((unused)) PPP_INFO_t *s_ppp_ccb)
{
    unsigned char buffer[MSG_BUF];
    U16 mulen;

    if (build_echo_reply(buffer,s_ppp_ccb,&mulen) < 0)
        return FALSE;
    drv_xmit(vrg_ccb, buffer, mulen);

    return TRUE;
}

STATUS A_create_up_event(__attribute__((unused)) struct rte_timer *tim, __attribute__((unused)) PPP_INFO_t *s_ppp_ccb)
{
    VRG_LOG(DBG, vrg_ccb->fp, s_ppp_ccb, PPPLOGMSG, "create up event");

    return TRUE;
}

STATUS A_create_down_event(__attribute__((unused)) struct rte_timer *tim, __attribute__((unused)) PPP_INFO_t *s_ppp_ccb)
{
    VRG_LOG(DBG, vrg_ccb->fp, s_ppp_ccb, PPPLOGMSG, "create down event");

    PPP_FSM(tim,s_ppp_ccb,E_DOWN);

    return TRUE;
}

STATUS A_zero_restart_count(__attribute__((unused)) struct rte_timer *tim, __attribute__((unused)) PPP_INFO_t *s_ppp_ccb)
{
    VRG_LOG(DBG, vrg_ccb->fp, s_ppp_ccb, PPPLOGMSG, "zero restart count");
    
    return TRUE;
}

STATUS A_send_padt(__attribute__((unused)) struct rte_timer *tim, __attribute__((unused)) PPP_INFO_t *s_ppp_ccb)
{
    if (build_padt(s_ppp_ccb) < 0)
        return FALSE;
    s_ppp_ccb->phase = END_PHASE;

    return TRUE;
}

STATUS A_create_close_to_lower_layer(__attribute__((unused)) struct rte_timer *tim, __attribute__((unused)) PPP_INFO_t *s_ppp_ccb)
{
    VRG_LOG(INFO, vrg_ccb->fp, s_ppp_ccb, PPPLOGMSG, "User %" PRIu16 " notify lower layer to close connection.\n", s_ppp_ccb->user_num);
    s_ppp_ccb->cp = 0;
    s_ppp_ccb->phase -= 2;
    rte_timer_stop(&(s_ppp_ccb->ppp_alive));
    PPP_FSM(tim,s_ppp_ccb,E_CLOSE);

    return TRUE;
}

void fsm_init(VRG_t *ccb)
{
    vrg_ccb = ccb;
}
