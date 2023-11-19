/*\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\
 	fsm.h
  
     Finite State Machine for PPP connection/call

  Designed by THE on Jan 14, 2019
/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\*/
#include 	<common.h>
#include 	"codec.h"

#ifndef _FSM_H_
#define _FSM_H_

typedef struct{
    U8   	state;
    U16   	event;
    U8   	next_state;
    STATUS 	(*hdl[10])(struct rte_timer *, PPP_INFO_t *);
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
	E_UNKNOWN, // for log usage, not for fsm
} PPP_EVENT_TYPE;

STATUS A_padi_timer_func(__attribute__((unused)) struct rte_timer *tim, __attribute__((unused)) PPP_INFO_t *s_ppp_ccb);
STATUS A_padr_timer_func(__attribute__((unused)) struct rte_timer *tim, __attribute__((unused)) PPP_INFO_t *s_ppp_ccb);
void fsm_init(void *ccb);

/*======================= external ==========================*/
#ifdef __cplusplus
extern	"C" {
#endif

#ifdef __cplusplus
}
#endif

#endif /* header */
