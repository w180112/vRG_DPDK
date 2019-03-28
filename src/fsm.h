/*\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\
 	fsm.h
  
     Finite State Machine for PPP connection/call

  Designed by THE on Jan 14, 2019
/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\*/
#include 	"codec.h"
#include 	<common.h>
#include 	"dpdk_send_recv.h"

#ifndef _PPP_FSM_H_
#define _PPP_FSM_H_

typedef struct{
    U8   	state;
    U16   	event;
    U8   	next_state;
    STATUS 	(*hdl[10])(int cp, tPPP_PORT *, struct ethhdr *, pppoe_header_t *, ppp_payload_t *, ppp_lcp_header_t *, ppp_lcp_options_t *);
} tPPP_STATE_TBL;

/*--------- STATE TYPE ----------*/
typedef enum {
    S_INIT,
    S_STARTING,
    S_CLOSED,
    S_STOPPED,
    S_CLOSING,
    S_STOPPING,
    S_REQUEST_SENT,
    S_ACK_RECEIVED,
    S_ACK_SENT,
    S_OPENED,
    S_INVLD,
} PPP_STATE;

/*----------------- EVENT TYPE --------------------
Q_ : Quest primitive 
E_ : Event */
typedef enum {
	E_UP,
	E_DOWN,
	E_OPEN,
	E_CLOSE,
	E_TIMEOUT_COUNTER_POSITIVE,
	E_TIMEOUT_COUNTER_EXPIRED,
	E_RECV_GOOD_CONFIG_REQUEST,
	E_RECV_BAD_CONFIG_REQUEST,
	E_RECV_CONFIG_ACK,
	E_RECV_CONFIG_NAK_REJ,
	E_RECV_TERMINATE_REQUEST,
	E_RECV_TERMINATE_ACK,
	E_RECV_UNKNOWN_CODE,
	E_RECV_GOOD_CODE_PROTOCOL_REJECT,
	E_RECV_BAD_CODE_PROTOCOL_REJECT,
	E_RECV_ECHO_REPLY_REQUEST_DISCARD_REQUEST,
} PPP_EVENT_TYPE;

typedef enum {
	MT_ppp_link,
	MT_ppp_crt,
	MT_ppp_tmr, 
	MT_ppp_peer,
} PPP_MAIL_TYPE;

/*======================= external ==========================*/
#ifdef __cplusplus
extern	"C" {
#endif

extern STATUS   PPP_FSM(int cp, tPPP_PORT *port_ccb, U16 event, /*void *arg,*/ struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_lcp_header_t *ppp_lcp, ppp_lcp_options_t *ppp_lcp_options); 

#ifdef __cplusplus
}
#endif

#endif /* header */
