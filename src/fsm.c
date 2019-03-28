#include    "fsm.h"

static STATUS   A_this_layer_start(int cp, tPPP_PORT*, struct ethhdr *, pppoe_header_t *, ppp_payload_t *, ppp_lcp_header_t *, ppp_lcp_options_t *);
static STATUS   A_send_config_request(int cp, tPPP_PORT*, struct ethhdr *, pppoe_header_t *, ppp_payload_t *, ppp_lcp_header_t *, ppp_lcp_options_t *);
static STATUS   A_this_layer_finish(int cp, tPPP_PORT*, struct ethhdr *, pppoe_header_t *, ppp_payload_t *, ppp_lcp_header_t *, ppp_lcp_options_t *);
static STATUS   A_send_terminate_ack(int cp, tPPP_PORT*, struct ethhdr *, pppoe_header_t *, ppp_payload_t *, ppp_lcp_header_t *, ppp_lcp_options_t *);
static STATUS   A_send_code_reject(int cp, tPPP_PORT*, struct ethhdr *, pppoe_header_t *, ppp_payload_t *, ppp_lcp_header_t *, ppp_lcp_options_t *);
static STATUS   A_create_down_event(int cp, tPPP_PORT*, struct ethhdr *, pppoe_header_t *, ppp_payload_t *, ppp_lcp_header_t *, ppp_lcp_options_t *);
static STATUS   A_create_up_event(int cp, tPPP_PORT*, struct ethhdr *, pppoe_header_t *, ppp_payload_t *, ppp_lcp_header_t *, ppp_lcp_options_t *);

static STATUS   A_send_config_ack(int cp, tPPP_PORT*, struct ethhdr *, pppoe_header_t *, ppp_payload_t *, ppp_lcp_header_t *, ppp_lcp_options_t *);
static STATUS   A_send_config_nak_rej(int cp, tPPP_PORT*, struct ethhdr *, pppoe_header_t *, ppp_payload_t *, ppp_lcp_header_t *, ppp_lcp_options_t *);
static STATUS   A_send_terminate_request(int cp, tPPP_PORT*, struct ethhdr *, pppoe_header_t *, ppp_payload_t *, ppp_lcp_header_t *, ppp_lcp_options_t *);
static STATUS   A_this_layer_up(int cp, tPPP_PORT*, struct ethhdr *, pppoe_header_t *, ppp_payload_t *, ppp_lcp_header_t *, ppp_lcp_options_t *);
static STATUS   A_this_layer_down(int cp, tPPP_PORT*, struct ethhdr *, pppoe_header_t *, ppp_payload_t *, ppp_lcp_header_t *, ppp_lcp_options_t *);
static STATUS   A_init_restart_count(int cp, tPPP_PORT*, struct ethhdr *, pppoe_header_t *, ppp_payload_t *, ppp_lcp_header_t *, ppp_lcp_options_t *);
static STATUS   A_send_echo_reply(int cp, tPPP_PORT*, struct ethhdr *, pppoe_header_t *, ppp_payload_t *, ppp_lcp_header_t *, ppp_lcp_options_t *);
static STATUS   A_create_up_event(int cp, tPPP_PORT*, struct ethhdr *, pppoe_header_t *, ppp_payload_t *, ppp_lcp_header_t *, ppp_lcp_options_t *);
static STATUS   A_create_down_event(int cp, tPPP_PORT*, struct ethhdr *, pppoe_header_t *, ppp_payload_t *, ppp_lcp_header_t *, ppp_lcp_options_t *);
static STATUS   A_zero_restart_count(int cp, tPPP_PORT*, struct ethhdr *, pppoe_header_t *, ppp_payload_t *, ppp_lcp_header_t *, ppp_lcp_options_t *);

tPPP_STATE_TBL  ppp_fsm_tbl[2][121] = { 
/*//////////////////////////////////////////////////////////////////////////////////
  	STATE   		EVENT           						      NEXT-STATE            HANDLER       
///////////////////////////////////////////////////////////////////////////////////\*/
{{ S_INIT,		  	E_UP,     							    	  	S_CLOSED,		    { 0 }},

/* these actions are "this layer start" (tls) and should retern "UP" event */
{ S_INIT,		  	E_OPEN,     						    		S_STARTING,		    { A_this_layer_start, 0 }},

{ S_INIT, 			E_CLOSE,							      		S_INIT, 		    { 0 }},	                                                      	  

/*---------------------------------------------------------------------------*/
{ S_STARTING,		E_UP,     							    		S_REQUEST_SENT,	  	{ A_send_config_request, /*A_init_restart_count,*/ 0 }},

{ S_STARTING,		E_OPEN,    							    		S_STARTING,		    { 0 }},

/* these actions are "this layer finish" (tlf) and should retern "DOWN" event */
{ S_STARTING,		E_CLOSE,    						    		S_INIT,			    { A_this_layer_finish, 0 }},

/*---------------------------------------------------------------------------*/
{ S_CLOSED,			E_DOWN, 							      		S_INIT,			    { 0 }},

{ S_CLOSED,			E_OPEN, 							      		S_REQUEST_SENT,	  	{ A_send_config_request, /*A_init_restart_count,*/ 0 }},

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

{ S_STOPPED,		E_RECV_GOOD_CONFIG_REQUEST,						S_ACK_SENT,		    { A_init_restart_count, A_send_config_request, A_send_config_ack, 0 }},

{ S_STOPPED,		E_RECV_BAD_CONFIG_REQUEST, 						S_REQUEST_SENT,	  	{ A_init_restart_count, A_send_config_request, A_send_config_nak_rej, 0 }},
	
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

{ S_REQUEST_SENT, 	E_CLOSE,										S_CLOSING, 			{ A_init_restart_count, A_send_terminate_request, 0 }},

{ S_REQUEST_SENT, 	E_TIMEOUT_COUNTER_POSITIVE,						S_REQUEST_SENT, 	{ A_send_config_request, 0 }},

/* may be with "PASSIVE" option, with this option, ppp will not exit but then just wait for a valid LCP packet from peer if there is not received form peer */
{ S_REQUEST_SENT, 	E_TIMEOUT_COUNTER_EXPIRED,						S_STOPPED, 			{ A_this_layer_finish, 0 }},

{ S_REQUEST_SENT, 	E_RECV_GOOD_CONFIG_REQUEST,						S_ACK_SENT,			{ A_send_config_ack, 0 }},

{ S_REQUEST_SENT, 	E_RECV_BAD_CONFIG_REQUEST,						S_REQUEST_SENT,		{ A_send_config_nak_rej, 0 }},

{ S_REQUEST_SENT, 	E_RECV_CONFIG_ACK,								S_ACK_RECEIVED,		{ A_init_restart_count, 0 }},

{ S_REQUEST_SENT, 	E_RECV_CONFIG_NAK_REJ,							S_REQUEST_SENT,		{ A_init_restart_count, A_send_config_request, 0 }},

{ S_REQUEST_SENT, 	E_RECV_TERMINATE_REQUEST,						S_REQUEST_SENT,		{ A_send_terminate_ack, 0 }},

{ S_REQUEST_SENT, 	E_RECV_TERMINATE_ACK,							S_REQUEST_SENT,		{ 0 }},

{ S_REQUEST_SENT, 	E_RECV_UNKNOWN_CODE,							S_REQUEST_SENT,		{ A_send_code_reject, 0 }},

{ S_REQUEST_SENT, 	E_RECV_GOOD_CODE_PROTOCOL_REJECT,				S_REQUEST_SENT,		{ 0 }},

{ S_REQUEST_SENT, 	E_RECV_BAD_CODE_PROTOCOL_REJECT,				S_STOPPED,			{ A_this_layer_finish, 0 }},

{ S_REQUEST_SENT, 	E_RECV_ECHO_REPLY_REQUEST_DISCARD_REQUEST, 		S_REQUEST_SENT,		{ 0 }},

/*---------------------------------------------------------------------------*/
{ S_ACK_RECEIVED, 	E_DOWN,											S_STARTING, 		{ 0 }},

{ S_ACK_RECEIVED, 	E_OPEN,											S_ACK_RECEIVED, 	{ 0 }},

{ S_ACK_RECEIVED, 	E_CLOSE,										S_CLOSING, 			{ A_init_restart_count, A_send_terminate_request, 0 }},

{ S_ACK_RECEIVED, 	E_TIMEOUT_COUNTER_POSITIVE,						S_REQUEST_SENT, 	{ A_send_config_request, 0 }},

/* may be with "PASSIVE" option, with this option, ppp will not exit but then just wait for a valid LCP packet from peer if there is not received form peer */
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

{ S_ACK_SENT, 		E_CLOSE,										S_CLOSING, 			{ A_init_restart_count, A_send_terminate_request, 0 }},
	
{ S_ACK_SENT, 		E_TIMEOUT_COUNTER_POSITIVE,						S_ACK_SENT, 		{ A_send_config_request, 0 }},

/* may be with "PASSIVE" option, with this option, ppp will not exit but then just wait for a valid LCP packet from peer if there is not received form peer */
{ S_ACK_SENT, 		E_TIMEOUT_COUNTER_EXPIRED,						S_STOPPED, 			{ A_this_layer_finish, 0 }},

{ S_ACK_SENT, 		E_RECV_GOOD_CONFIG_REQUEST,						S_ACK_SENT,			{ A_send_config_ack, 0 }},

{ S_ACK_SENT, 		E_RECV_BAD_CONFIG_REQUEST,						S_REQUEST_SENT,		{ A_send_config_nak_rej, 0 }},

{ S_ACK_SENT, 		E_RECV_CONFIG_ACK,								S_OPENED,			{ A_init_restart_count, A_this_layer_up, 0 }},

{ S_ACK_SENT, 		E_RECV_CONFIG_NAK_REJ,							S_ACK_SENT,			{ A_init_restart_count, A_send_config_request, 0 }},

{ S_ACK_SENT, 		E_RECV_TERMINATE_REQUEST,						S_REQUEST_SENT,		{ A_send_terminate_ack, 0 }},

{ S_ACK_SENT, 		E_RECV_TERMINATE_ACK,							S_ACK_SENT,			{ 0 }},

{ S_ACK_SENT, 		E_RECV_UNKNOWN_CODE,							S_ACK_SENT,			{ A_send_code_reject, 0 }},

{ S_ACK_SENT, 		E_RECV_GOOD_CODE_PROTOCOL_REJECT,				S_ACK_SENT,			{ 0 }},

{ S_ACK_SENT, 		E_RECV_BAD_CODE_PROTOCOL_REJECT,				S_STOPPED,			{ A_this_layer_finish, 0 }},

{ S_ACK_SENT, 		E_RECV_ECHO_REPLY_REQUEST_DISCARD_REQUEST, 		S_ACK_SENT,			{ 0 }},

/*---------------------------------------------------------------------------*/
{ S_OPENED, 		E_DOWN,											S_STARTING, 		{ A_this_layer_down, 0 }},

{ S_OPENED, 		E_OPEN,											S_OPENED, 			{ A_create_down_event, A_create_up_event, 0 }},

{ S_OPENED, 		E_CLOSE,										S_CLOSING, 			{ A_this_layer_down, A_init_restart_count, A_send_terminate_request, 0 }},

{ S_OPENED, 		E_RECV_GOOD_CONFIG_REQUEST,						S_ACK_SENT,			{ A_this_layer_down, A_send_config_request, A_send_config_ack, 0 }},

{ S_OPENED, 		E_RECV_BAD_CONFIG_REQUEST,						S_REQUEST_SENT,		{ A_this_layer_down, A_send_config_request, A_send_config_nak_rej, 0 }},

/* we should silently discard invalid ack/nak/rej packets and not affect transistions of the automaton 
 * so we just send a configure request packet and do nothing 
 * note: in RFC 1661 it rules we whould log this packet because it`s impossible that a correctly formed packet
         will arrive through a coincidentally-timed cross-connection, but we will skip to log in our implementation
 */
{ S_OPENED, 		E_RECV_CONFIG_ACK,								S_REQUEST_SENT,		{ A_this_layer_down, A_send_config_request, 0 }},
	
{ S_OPENED, 		E_RECV_CONFIG_NAK_REJ,							S_REQUEST_SENT,		{ A_this_layer_down, A_send_config_request, 0 }},

{ S_OPENED, 		E_RECV_TERMINATE_REQUEST,						S_STOPPING,			{ A_this_layer_down, A_zero_restart_count, A_send_terminate_ack, 0 }},

{ S_OPENED, 		E_RECV_TERMINATE_ACK,							S_REQUEST_SENT,		{ A_this_layer_down, A_send_config_request, 0 }},

{ S_OPENED, 		E_RECV_UNKNOWN_CODE,							S_OPENED,			{ A_send_code_reject, 0 }},

{ S_OPENED, 		E_RECV_GOOD_CODE_PROTOCOL_REJECT,				S_OPENED,			{ 0 }},

{ S_OPENED, 		E_RECV_BAD_CODE_PROTOCOL_REJECT,				S_STOPPING,			{ A_this_layer_down, A_init_restart_count, A_send_terminate_request, 0 }},

{ S_OPENED, 		E_RECV_ECHO_REPLY_REQUEST_DISCARD_REQUEST,		S_OPENED,			{ A_send_echo_reply, 0 }},

{ S_INVLD, 0 }},

{{ S_INIT,		  	E_UP,     							    		S_CLOSED,		    { 0 }},

/* these actions are "this layer start" (tls) and should retern "UP" event */
{ S_INIT,		  	E_OPEN,     						    		S_STARTING,		    { A_this_layer_start, 0 }},

{ S_INIT, 			E_CLOSE,							      		S_INIT, 		    { 0 }},	                                                      	  

/*---------------------------------------------------------------------------*/
{ S_STARTING,		E_UP,     							    		S_REQUEST_SENT,	  	{ A_send_config_request, /*A_init_restart_count,*/ 0 }},

{ S_STARTING,		E_OPEN,    							    		S_STARTING,		    { 0 }},

/* these actions are "this layer finish" (tlf) and should retern "DOWN" event */
{ S_STARTING,		E_CLOSE,    						    		S_INIT,			    { A_this_layer_finish, 0 }},

/*---------------------------------------------------------------------------*/
{ S_CLOSED,			E_DOWN, 							      		S_INIT,			    { 0 }},

{ S_CLOSED,			E_OPEN, 							      		S_REQUEST_SENT,	  	{ A_send_config_request, /*A_init_restart_count,*/ 0 }},

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

{ S_STOPPED,		E_RECV_GOOD_CONFIG_REQUEST,						S_ACK_SENT,		    { A_init_restart_count, A_send_config_request, A_send_config_ack, 0 }},

{ S_STOPPED,		E_RECV_BAD_CONFIG_REQUEST, 						S_REQUEST_SENT,	  	{ A_init_restart_count, A_send_config_request, A_send_config_nak_rej, 0 }},

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
{ S_CLOSING, 	E_DOWN,								     S_INIT,			      { 0 }},

{ S_CLOSING, 	E_OPEN,								     S_STOPPING,		    { A_create_down_event, A_create_up_event, 0 }},

{ S_CLOSING, 	E_CLOSE,							     S_CLOSING,		      { 0 }},

{ S_CLOSING, 	E_TIMEOUT_COUNTER_POSITIVE,S_CLOSING,		      { A_send_terminate_request, 0 }},

{ S_CLOSING, 	E_TIMEOUT_COUNTER_EXPIRED, S_CLOSED,		      { A_this_layer_finish, 0 }},

{ S_CLOSING,	E_RECV_GOOD_CONFIG_REQUEST,S_CLOSING,		      { 0 }},

{ S_CLOSING,	E_RECV_BAD_CONFIG_REQUEST, S_CLOSING,		      { 0 }},

{ S_CLOSING,	E_RECV_CONFIG_ACK, 				 S_CLOSING,		      { 0 }},

{ S_CLOSING,	E_RECV_CONFIG_NAK_REJ, 		 S_CLOSING,		      { 0 }},

{ S_CLOSING,	E_RECV_TERMINATE_REQUEST,  S_CLOSING,		      { A_send_terminate_ack, 0 }},

{ S_CLOSING,	E_RECV_TERMINATE_ACK, 		 S_CLOSED,		      { A_create_down_event, A_create_up_event, 0 }},

{ S_CLOSING,	E_RECV_UNKNOWN_CODE, 			 S_CLOSING,		      { A_send_code_reject, 0 }},

/* recv code/protocol reject when rejected value is acceptable, 
	such as a Code-Reject of an extended code, 
	or a Protocol-Reject of a NCP */ 
{ S_CLOSING,	E_RECV_GOOD_CODE_PROTOCOL_REJECT, S_CLOSING,  { 0 }},

{ S_CLOSING,	E_RECV_BAD_CODE_PROTOCOL_REJECT, 	S_CLOSED,		{ A_this_layer_finish, 0 }},

{ S_CLOSING,	E_RECV_ECHO_REPLY_REQUEST_DISCARD_REQUEST, S_CLOSING,{ 0 }},

/*---------------------------------------------------------------------------*/
{ S_STOPPING, E_DOWN,								     S_STARTING, 	      { 0 }},

{ S_STOPPING, E_OPEN,								     S_STOPPING, 	      { A_create_down_event, A_create_up_event, 0 }},

{ S_STOPPING, E_CLOSE,							     S_CLOSING, 		    { 0 }},

{ S_STOPPING, E_TIMEOUT_COUNTER_POSITIVE,S_STOPPING,		    { A_send_terminate_request, 0 }},

{ S_STOPPING, E_TIMEOUT_COUNTER_EXPIRED, S_STOPPED,		      { A_this_layer_finish, 0 }},

{ S_STOPPING,	E_RECV_GOOD_CONFIG_REQUEST,     	S_STOPPING,		{ 0 }},

{ S_STOPPING,	E_RECV_BAD_CONFIG_REQUEST,     		S_STOPPING,		{ 0 }},

{ S_STOPPING,	E_RECV_CONFIG_ACK, 					S_STOPPING,		{ 0 }},

{ S_STOPPING,	E_RECV_CONFIG_NAK_REJ, 				S_STOPPING,		{ 0 }},

{ S_STOPPING,	E_RECV_TERMINATE_REQUEST, 			S_STOPPING,		{ A_send_terminate_ack, 0 }},

{ S_STOPPING,	E_RECV_TERMINATE_ACK, 				S_STOPPED,		{ A_create_down_event, A_create_up_event, 0 }},

{ S_STOPPING,	E_RECV_UNKNOWN_CODE, 				S_STOPPING,		{ A_send_code_reject, 0 }},

/* recv code/protocol reject when rejected value is acceptable, 
	such as a Code-Reject of an extended code, 
	or a Protocol-Reject of a NCP */ 
{ S_STOPPING,	E_RECV_GOOD_CODE_PROTOCOL_REJECT, 	S_STOPPING,		{ 0 }},

{ S_STOPPING,	E_RECV_BAD_CODE_PROTOCOL_REJECT, 	S_STOPPED,		{ A_this_layer_finish, 0 }},

{ S_STOPPING,	E_RECV_ECHO_REPLY_REQUEST_DISCARD_REQUEST, S_STOPPING,{ 0 }},

/*---------------------------------------------------------------------------*/
{ S_REQUEST_SENT, E_DOWN,							S_STARTING, 	{ 0 }},

{ S_REQUEST_SENT, E_OPEN,							S_REQUEST_SENT, { 0 }},

{ S_REQUEST_SENT, E_CLOSE,							S_CLOSING, 		{ A_init_restart_count, A_send_terminate_request, 0 }},

{ S_REQUEST_SENT, E_TIMEOUT_COUNTER_POSITIVE,		S_REQUEST_SENT, { A_send_config_request, 0 }},

/* may be with "PASSIVE" option, with this option, ppp will not exit but then just wait for a valid LCP packet from peer if there is not received form peer */
{ S_REQUEST_SENT, E_TIMEOUT_COUNTER_EXPIRED,		S_STOPPED, 		{ A_this_layer_finish, 0 }},

{ S_REQUEST_SENT, E_RECV_GOOD_CONFIG_REQUEST,		S_ACK_SENT,		{ A_send_config_ack, 0 }},

{ S_REQUEST_SENT, E_RECV_BAD_CONFIG_REQUEST,		S_REQUEST_SENT,	{ A_send_config_nak_rej, 0 }},

{ S_REQUEST_SENT, E_RECV_CONFIG_ACK,				S_ACK_RECEIVED,	{ A_init_restart_count, 0 }},

{ S_REQUEST_SENT, E_RECV_CONFIG_NAK_REJ,			S_REQUEST_SENT,	{ A_init_restart_count, A_send_config_request, 0 }},

{ S_REQUEST_SENT, E_RECV_TERMINATE_REQUEST,			S_REQUEST_SENT,	{ A_send_terminate_ack, 0 }},

{ S_REQUEST_SENT, E_RECV_TERMINATE_ACK,				S_REQUEST_SENT,	{ 0 }},

{ S_REQUEST_SENT, E_RECV_UNKNOWN_CODE,				S_REQUEST_SENT,	{ A_send_code_reject, 0 }},

{ S_REQUEST_SENT, E_RECV_GOOD_CODE_PROTOCOL_REJECT,	S_REQUEST_SENT,	{ 0 }},

{ S_REQUEST_SENT, E_RECV_BAD_CODE_PROTOCOL_REJECT,	S_STOPPED,		{ A_this_layer_finish, 0 }},

{ S_REQUEST_SENT, E_RECV_ECHO_REPLY_REQUEST_DISCARD_REQUEST, S_REQUEST_SENT,	{ 0 }},

/*---------------------------------------------------------------------------*/
{ S_ACK_RECEIVED, E_DOWN,							S_STARTING, 	{ 0 }},

{ S_ACK_RECEIVED, E_OPEN,							S_ACK_RECEIVED, { 0 }},

{ S_ACK_RECEIVED, E_CLOSE,							S_CLOSING, 		{ A_init_restart_count, A_send_terminate_request, 0 }},

{ S_ACK_RECEIVED, E_TIMEOUT_COUNTER_POSITIVE,		S_REQUEST_SENT, { A_send_config_request, 0 }},

/* may be with "PASSIVE" option, with this option, ppp will not exit but then just wait for a valid LCP packet from peer if there is not received form peer */
{ S_ACK_RECEIVED, E_TIMEOUT_COUNTER_EXPIRED,		S_STOPPED, 		{ A_this_layer_finish, 0 }},

{ S_ACK_RECEIVED, E_RECV_GOOD_CONFIG_REQUEST,		S_OPENED,		{ A_send_config_ack, A_this_layer_up, 0 }},

{ S_ACK_RECEIVED, E_RECV_BAD_CONFIG_REQUEST,		S_ACK_RECEIVED,	{ A_send_config_nak_rej, 0 }},

/* we should silently discard invalid ack/nak/rej packets and not affect transistions of the automaton 
 * so we just send a configure request packet and do nothing 
 * note: in RFC 1661 it rules we whould log this packet because it`s impossible that a correctly formed packet
         will arrive through a coincidentally-timed cross-connection, but we will skip to log in our implementation
 */
{ S_ACK_RECEIVED, E_RECV_CONFIG_ACK,				S_REQUEST_SENT,	{ A_send_config_request, 0 }},

{ S_ACK_RECEIVED, E_RECV_CONFIG_NAK_REJ,			S_REQUEST_SENT,	{ A_send_config_request, 0 }},

{ S_ACK_RECEIVED, E_RECV_TERMINATE_REQUEST,			S_REQUEST_SENT,	{ A_send_terminate_ack, 0 }},

{ S_ACK_RECEIVED, E_RECV_TERMINATE_ACK,				S_REQUEST_SENT,	{ 0 }},

{ S_ACK_RECEIVED, E_RECV_UNKNOWN_CODE,				S_ACK_RECEIVED,	{ A_send_code_reject, 0 }},

{ S_ACK_RECEIVED, E_RECV_GOOD_CODE_PROTOCOL_REJECT,	S_REQUEST_SENT,	{ 0 }},

{ S_ACK_RECEIVED, E_RECV_BAD_CODE_PROTOCOL_REJECT,	S_STOPPED,		{ A_this_layer_finish, 0 }},

{ S_ACK_RECEIVED, E_RECV_ECHO_REPLY_REQUEST_DISCARD_REQUEST, S_ACK_RECEIVED,	{ 0 }},

/*---------------------------------------------------------------------------*/
{ S_ACK_SENT, 	E_DOWN,								S_STARTING, 	{ 0 }},

{ S_ACK_SENT, 	E_OPEN,								S_ACK_SENT, 	{ 0 }},

{ S_ACK_SENT, 	E_CLOSE,							S_CLOSING, 		{ A_init_restart_count, A_send_terminate_request, 0 }},
	
{ S_ACK_SENT, 	E_TIMEOUT_COUNTER_POSITIVE,			S_ACK_SENT, 	{ A_send_config_request, 0 }},

/* may be with "PASSIVE" option, with this option, ppp will not exit but then just wait for a valid LCP packet from peer if there is not received form peer */
{ S_ACK_SENT, 	E_TIMEOUT_COUNTER_EXPIRED,			S_STOPPED, 		{ A_this_layer_finish, 0 }},

{ S_ACK_SENT, 	E_RECV_GOOD_CONFIG_REQUEST,			S_ACK_SENT,		{ A_send_config_ack, 0 }},

{ S_ACK_SENT, 	E_RECV_BAD_CONFIG_REQUEST,			S_REQUEST_SENT,	{ A_send_config_nak_rej, 0 }},

{ S_ACK_SENT, 	E_RECV_CONFIG_ACK,					S_OPENED,		{ A_init_restart_count, A_this_layer_up, 0 }},

{ S_ACK_SENT, 	E_RECV_CONFIG_NAK_REJ,				S_ACK_SENT,		{ A_init_restart_count, A_send_config_request, 0 }},

{ S_ACK_SENT, 	E_RECV_TERMINATE_REQUEST,			S_REQUEST_SENT,	{ A_send_terminate_ack, 0 }},

{ S_ACK_SENT, 	E_RECV_TERMINATE_ACK,				S_ACK_SENT,		{ 0 }},

{ S_ACK_SENT, 	E_RECV_UNKNOWN_CODE,				S_ACK_SENT,		{ A_send_code_reject, 0 }},

{ S_ACK_SENT, 	E_RECV_GOOD_CODE_PROTOCOL_REJECT,	S_ACK_SENT,		{ 0 }},

{ S_ACK_SENT, 	E_RECV_BAD_CODE_PROTOCOL_REJECT,	S_STOPPED,		{ A_this_layer_finish, 0 }},

{ S_ACK_SENT, 	E_RECV_ECHO_REPLY_REQUEST_DISCARD_REQUEST, S_ACK_SENT,	{ 0 }},

/*---------------------------------------------------------------------------*/
{ S_OPENED, 	E_DOWN,								S_STARTING, 	{ A_this_layer_down, 0 }},

{ S_OPENED, 	E_OPEN,								S_OPENED, 		{ A_create_down_event, A_create_up_event, 0 }},

{ S_OPENED, 	E_CLOSE,							S_CLOSING, 		{ A_this_layer_down, A_init_restart_count, A_send_terminate_request, 0 }},

{ S_OPENED, 	E_RECV_GOOD_CONFIG_REQUEST,			S_ACK_SENT,		{ A_this_layer_down, A_send_config_request, A_send_config_ack, 0 }},

{ S_OPENED, 	E_RECV_BAD_CONFIG_REQUEST,			S_REQUEST_SENT,	{ A_this_layer_down, A_send_config_request, A_send_config_nak_rej, 0 }},

/* we should silently discard invalid ack/nak/rej packets and not affect transistions of the automaton 
 * so we just send a configure request packet and do nothing 
 * note: in RFC 1661 it rules we whould log this packet because it`s impossible that a correctly formed packet
         will arrive through a coincidentally-timed cross-connection, but we will skip to log in our implementation
 */
{ S_OPENED, 	E_RECV_CONFIG_ACK,					S_REQUEST_SENT,	{ A_this_layer_down, A_send_config_request, 0 }},
	
{ S_OPENED, 	E_RECV_CONFIG_NAK_REJ,				S_REQUEST_SENT,	{ A_this_layer_down, A_send_config_request, 0 }},

{ S_OPENED, 	E_RECV_TERMINATE_REQUEST,			S_STOPPING,		{ A_this_layer_down, A_zero_restart_count, A_send_terminate_ack, 0 }},

{ S_OPENED, 	E_RECV_TERMINATE_ACK,				S_REQUEST_SENT,	{ A_this_layer_down, A_send_config_request, 0 }},

{ S_OPENED, 	E_RECV_UNKNOWN_CODE,				S_OPENED,		{ A_send_code_reject, 0 }},

{ S_OPENED, 	E_RECV_GOOD_CODE_PROTOCOL_REJECT,	S_OPENED,		{ 0 }},

{ S_OPENED, 	E_RECV_BAD_CODE_PROTOCOL_REJECT,	S_STOPPING,		{ A_this_layer_down, A_init_restart_count, A_send_terminate_request, 0 }},

{ S_OPENED, 	E_RECV_ECHO_REPLY_REQUEST_DISCARD_REQUEST, S_OPENED,{ A_send_echo_reply, 0 }},

{ S_INVLD, 0 }}
};

/***********************************************************************
 * PPP_FSM
 *
 * purpose : finite state machine.
 * input   : tnnl - tunnel pointer
 *           event -
 *           arg - signal(primitive) or pdu
 * return  : error status
 ***********************************************************************/
STATUS PPP_FSM(int cp, tPPP_PORT *port_ccb, U16 event, /*void *arg,*/ struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_lcp_header_t *ppp_lcp, ppp_lcp_options_t *ppp_lcp_options)
{	
    register int  	i,j;
    int			    retval;

    if (!port_ccb) {
        return FALSE;
    }
    
    /* Find a matched state */
    for(i=0; ppp_fsm_tbl[cp][i].state!=S_INVLD; i++)
        if (ppp_fsm_tbl[cp][i].state == port_ccb->state)
            break;
    printf("cur state = %x, control protocol = %d\n", ppp_fsm_tbl[cp][i].state, cp);

    if (ppp_fsm_tbl[cp][i].state == S_INVLD) {
        return FALSE;
    }

    /*
     * Find a matched event in a specific state.
     * Note : a state can accept several events.
     */
    for(;ppp_fsm_tbl[cp][i].state==port_ccb->state; i++)
        if (ppp_fsm_tbl[cp][i].event == event)
            break;
    
    if (ppp_fsm_tbl[cp][i].state != port_ccb->state) { /* search until meet the next state */
  		return TRUE; /* still pass to endpoint */
    }
    
    /* Correct state found */
    if (port_ccb->state != ppp_fsm_tbl[cp][i].next_state) {
        port_ccb->state = ppp_fsm_tbl[cp][i].next_state;
    }
    
    for(j=0; ppp_fsm_tbl[cp][i].hdl[j]; j++) {
       	retval = (*ppp_fsm_tbl[cp][i].hdl[j])(cp,port_ccb,eth_hdr,pppoe_header,ppp_payload,ppp_lcp,ppp_lcp_options);
       	if (!retval)  
            return TRUE;
    }
    return TRUE;
}

/* this layer up/down/start/finish */
STATUS A_this_layer_start(int cp, tPPP_PORT *port_ccb, struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_lcp_header_t *ppp_lcp, ppp_lcp_options_t *ppp_lcp_options)
{
    PPP_FSM(cp,port_ccb,E_UP,eth_hdr,pppoe_header,ppp_payload,ppp_lcp,ppp_lcp_options);

    return TRUE;
}

STATUS A_this_layer_finish(int cp, tPPP_PORT *port_ccb, struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_lcp_header_t *ppp_lcp, ppp_lcp_options_t *ppp_lcp_options)
{
    PPP_FSM(cp,port_ccb,E_DOWN,eth_hdr,pppoe_header,ppp_payload,ppp_lcp,ppp_lcp_options);

    return TRUE;
}

STATUS A_this_layer_up(int cp, tPPP_PORT *port_ccb, struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_lcp_header_t *ppp_lcp, ppp_lcp_options_t *ppp_lcp_options)
{
	unsigned char buffer[MSG_BUF];
    uint16_t mulen;

	if (ppp_payload->ppp_protocol == htons(LCP_PROTOCOL)) {
    	memset(buffer,0,MSG_BUF);
    	if (build_auth_request_pap(buffer,eth_hdr,pppoe_header,ppp_payload,ppp_lcp,ppp_lcp_options,&mulen) < 0)
    		return FALSE;
    	drv_xmit(buffer,mulen);
    }
    else if (ppp_payload->ppp_protocol == htons(IPCP_PROTOCOL)) {
    	//DPDK enqueue
    	puts("start to send data via pppoe session.");
    }
    printf("this layer up\n");

    return TRUE;
}

STATUS A_this_layer_down(int cp, tPPP_PORT *port_ccb, struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_lcp_header_t *ppp_lcp, ppp_lcp_options_t *ppp_lcp_options)
{
    printf("this layer down\n");

    return TRUE;
}

STATUS A_init_restart_count(int cp, tPPP_PORT *port_ccb, struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_lcp_header_t *ppp_lcp, ppp_lcp_options_t *ppp_lcp_options)
{
    printf("init restart count\n");

    return TRUE;
}

STATUS A_send_config_request(int cp, tPPP_PORT *port_ccb, struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_lcp_header_t *ppp_lcp, ppp_lcp_options_t *ppp_lcp_options)
{
    unsigned char buffer[MSG_BUF];
    uint16_t mulen;

    if (build_config_request(cp,buffer,eth_hdr,pppoe_header,ppp_payload,ppp_lcp,ppp_lcp_options,&mulen) < 0)
        return FALSE;
    drv_xmit(buffer,mulen);

    return TRUE;
}

STATUS A_send_config_nak_rej(int cp, tPPP_PORT *port_ccb, struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_lcp_header_t *ppp_lcp, ppp_lcp_options_t *ppp_lcp_options)
{
    unsigned char buffer[MSG_BUF];
    uint16_t mulen;

    if (build_config_nak_rej(cp,buffer,eth_hdr,pppoe_header,ppp_payload,ppp_lcp,ppp_lcp_options,&mulen) < 0)
        return FALSE;
    drv_xmit(buffer,mulen);

    return TRUE;
}

STATUS A_send_config_ack(int cp, tPPP_PORT *port_ccb, struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_lcp_header_t *ppp_lcp, ppp_lcp_options_t *ppp_lcp_options)
{
    unsigned char buffer[MSG_BUF];
    uint16_t mulen;

    if (build_config_ack(cp,buffer,eth_hdr,pppoe_header,ppp_payload,ppp_lcp,ppp_lcp_options,&mulen) < 0)
        return FALSE;
    drv_xmit(buffer,mulen);

    return TRUE;
}

STATUS A_send_terminate_request(int cp, tPPP_PORT *port_ccb, struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_lcp_header_t *ppp_lcp, ppp_lcp_options_t *ppp_lcp_options)
{
    unsigned char buffer[MSG_BUF];
    uint16_t mulen;

    if (build_terminate_request(cp,buffer,eth_hdr,pppoe_header,ppp_payload,ppp_lcp,ppp_lcp_options,&mulen) < 0)
        return FALSE;
    drv_xmit(buffer,mulen);

    return TRUE;
}

STATUS A_send_terminate_ack(int cp, tPPP_PORT *port_ccb, struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_lcp_header_t *ppp_lcp, ppp_lcp_options_t *ppp_lcp_options)
{
    unsigned char buffer[MSG_BUF];
    uint16_t mulen;

    if (build_terminate_ack(cp,buffer,eth_hdr,pppoe_header,ppp_payload,ppp_lcp,ppp_lcp_options,&mulen) < 0)
        return FALSE;
    drv_xmit(buffer,mulen);

    return TRUE;
}

STATUS A_send_code_reject(int cp, tPPP_PORT *port_ccb, struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_lcp_header_t *ppp_lcp, ppp_lcp_options_t *ppp_lcp_options)
{
    unsigned char buffer[MSG_BUF];
    uint16_t mulen;

    if (build_code_reject(cp,buffer,eth_hdr,pppoe_header,ppp_payload,ppp_lcp,ppp_lcp_options,&mulen) < 0)
        return FALSE;
    drv_xmit(buffer,mulen);

    return TRUE;
}

STATUS A_send_echo_reply(int cp, tPPP_PORT *port_ccb, struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_lcp_header_t *ppp_lcp, ppp_lcp_options_t *ppp_lcp_options)
{
    unsigned char buffer[MSG_BUF];
    uint16_t mulen;

    if (build_echo_reply(buffer,eth_hdr,pppoe_header,ppp_payload,ppp_lcp,ppp_lcp_options,&mulen) < 0)
        return FALSE;
    drv_xmit(buffer,mulen);
    printf("send echo reply\n");

    return TRUE;
}

STATUS A_create_up_event(int cp, tPPP_PORT *port_ccb, struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_lcp_header_t *ppp_lcp, ppp_lcp_options_t *ppp_lcp_options)
{
    printf("create up event\n");

    return TRUE;
}

STATUS A_create_down_event(int cp, tPPP_PORT *port_ccb, struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_lcp_header_t *ppp_lcp, ppp_lcp_options_t *ppp_lcp_options)
{
    printf("create down event\n");

    return TRUE;
}

STATUS A_zero_restart_count(int cp, tPPP_PORT *port_ccb, struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_lcp_header_t *ppp_lcp, ppp_lcp_options_t *ppp_lcp_options)
{
    printf("zero restart count\n");

    return TRUE;
}