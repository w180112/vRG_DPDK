/*\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\
  DP.H

  Designed by THE on JAN 21, 2021
/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\*/

#ifndef _DP_H_
#define _DP_H_

#include "vrg.h"

void drv_xmit(VRG_t *vrg_ccb, U8 *mu, U16 mulen);
int wan_recvd(void *arg);
int uplink(void *arg);
int downlink(void *arg);
int gateway(void *arg);
int lan_recvd(void *arg);
int PORT_INIT(VRG_t *vrg_ccb, U16 port);

#endif