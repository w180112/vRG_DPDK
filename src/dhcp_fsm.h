/*\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\
 	dhcp_fsm.h
  
     Finite State Machine for DHCP connection/call

  Designed by THE on Mar 21, 2021
/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\*/
#ifndef _DHCP_FSM_H_
#define _DHCP_FSM_H_

#include <common.h>
#include <rte_timer.h>
#include "dhcp_codec.h"

typedef struct{
    U8   	state;
    U16   	event;
    U8   	next_state;
    STATUS 	(*hdl[10])(struct rte_timer *, dhcp_ccb_t *);
} tDHCP_STATE_TBL;

/*--------- STATE TYPE ----------*/
typedef enum {
    S_DHCP_INIT = 1,
    S_DHCP_DISCOVER_RECV,
    S_DHCP_OFFER_SENT,
    S_DHCP_REQUEST_RECV,
    S_DHCP_ACK_SENT,
    S_DHCP_NAK_SENT,
    S_DHCP_INVLD,
} DHCP_STATE;

/*----------------- EVENT TYPE --------------------
Q_ : Quest primitive 
E_ : Event */
typedef enum {
	E_DISCOVER = 1,
	E_OFFER,
	E_GOOD_REQUEST,
    E_BAD_REQUEST,
	E_ACK,
	E_NAK,
    E_TIMEOUT,
    E_RELEASE,
} DHCP_EVENT_TYPE;

/*======================= external ==========================*/
#ifdef __cplusplus
extern	"C" {
#endif

#ifdef __cplusplus
}
#endif

#endif /* header */