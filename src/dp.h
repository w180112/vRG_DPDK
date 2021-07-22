/*\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\
  DP.H

  Designed by THE on JAN 21, 2021
/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\*/

#ifndef _DP_H_
#define _DP_H_

extern void drv_xmit(U8 *mu, U16 mulen);
extern int wan_recvd(void);
extern int uplink(void);
extern int downlink(void);
extern int gateway(void);
extern int lan_recvd(void);
extern int PORT_INIT(U16 port);
extern int control_plane_dequeue(tVRG_MBX **mail);

#endif