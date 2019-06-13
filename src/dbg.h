/*\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\
  DBG.H

  Designed by THE on JUN 11, 2019
/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\*/

#ifndef _DBG_H_
#define _DBG_H_

#define	DBGLVL1		1
#define DBGLVL2		2

extern 	void 		DBG_PPP(U8 level, tPPP_PORT *port_ccb, const char *fmt,...);
extern  char 		*PPP_state2str(U16 state);
extern  U8       	pppDbgFlag;
#endif