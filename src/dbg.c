/**************************************************************************
 * DBG.C
 *
 * Debug methods for ppp detection
 *
 * Created by THE on JUN 11,'19
 **************************************************************************/

#include    <common.h>
#include 	<rte_byteorder.h>
#include	"pppd.h"
#include 	"fsm.h"
#include    "dbg.h"

#define 	DBG_PPP_MSG_LEN     		256

char 		*PPP_state2str(U16 state);
	
U8       	pppDbgFlag=1;

/***************************************************
 * DBG_PPP:
 ***************************************************/	
void DBG_PPP(U8 level, tPPP_PORT *port_ccb, const char *fmt,...)
{
	va_list ap; /* points to each unnamed arg in turn */
	char    buf[256], msg[DBG_PPP_MSG_LEN], sstr[20];
	
	//user offer level must > system requirement
    if (pppDbgFlag < level)
    	return;

	va_start(ap, fmt); /* set ap pointer to 1st unnamed arg */
    vsnprintf(msg, DBG_PPP_MSG_LEN, fmt, ap);
    
    if (port_ccb) {
    	strcpy(sstr,PPP_state2str(port_ccb->ppp_phase[port_ccb->cp].state));
    	sprintf(buf,"pppd> Session id [%x.%s] ", rte_be_to_cpu_16(port_ccb->session_id), sstr);
    }
	else
		sprintf(buf,"pppd> ");

	strcat(buf,msg);
   	printf("%s",buf);
    va_end(ap);
}

/*-------------------------------------------------------------------
 * PPP_state2str
 *
 * input : state
 * return: string of corresponding state value
 *------------------------------------------------------------------*/
char *PPP_state2str(U16 state)
{
	static struct {
		PPP_STATE	state;
		char		str[20];
	} ppp_state_desc_tbl[] = {
    	{ S_INIT,  			"INIT  		 " },
    	{ S_STARTING,  		"STARTING    " },
    	{ S_CLOSED,  		"CLOSED 	 " },
    	{ S_STOPPED,		"STOPPED 	 " },
    	{ S_CLOSING,  		"CLOSING 	 " },
    	{ S_STOPPING,		"STOPPONG	 " },
    	{ S_REQUEST_SENT,  	"REQUEST_SENT" },
    	{ S_ACK_RECEIVED,  	"ACK_RECEIVED" },
    	{ S_ACK_SENT,		"ACK_SENT 	 " },
    	{ S_OPENED,  		"OPENED 	 " },
    	{ S_INVLD,			"Unknwn		 " },
	};

	U8  i;
	
	for(i=0; ppp_state_desc_tbl[i].state != S_INVLD; i++) {
		if (ppp_state_desc_tbl[i].state == state)  break;
	}
	if (ppp_state_desc_tbl[i].state == S_INVLD)
		return NULL;

	return ppp_state_desc_tbl[i].str;
}
