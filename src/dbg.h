/*\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\
  DBG.H

  Designed by THE on JUN 11, 2019
/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\*/

#ifndef _DBG_H_
#define _DBG_H_

#define	DBGPPP		1
#define DBGDHCP		2

extern 	void 		DBG_vRG(U8 level, U8 *ptr, const char *fmt,...);
extern  char 		*PPP_state2str(U16 state);
extern  char 		*DHCP_state2str(U16 state);
extern  U8      vRGDbgFlag;
#endif