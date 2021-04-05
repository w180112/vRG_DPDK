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
#include 	"dhcp_fsm.h"
#include    "dbg.h"

#define 	DBG_VRG_MSG_LEN     		256

char 		*PPP_state2str(U16 state);
char 		*DHCP_state2str(U16 state);
	
U8       	vRGDbgFlag=1;

/***************************************************
 * DBG_vRG:
 ***************************************************/	
void DBG_vRG(U8 level, U8 *ptr, const char *fmt,...)
{
	va_list ap; /* points to each unnamed arg in turn */
	char    buf[256], msg[DBG_VRG_MSG_LEN], sstr[20];
	
	//user offer level must > system requirement
    if (vRGDbgFlag > level)
    	return;

	va_start(ap, fmt); /* set ap pointer to 1st unnamed arg */
    vsnprintf(msg, DBG_VRG_MSG_LEN, fmt, ap);
    if (level == DBGPPP) {
		tPPP_PORT *port_ccb = (tPPP_PORT *)ptr;
    	if (port_ccb) {
    		strcpy(sstr,PPP_state2str(port_ccb->ppp_phase[port_ccb->cp].state));
    		sprintf(buf,"pppd> Session id [%x.%s] ", rte_be_to_cpu_16(port_ccb->session_id), sstr);
    	}
		else
			sprintf(buf,"pppd> ");
	}
	else if (level == DBGDHCP) {
		dhcp_ccb_t *dhcp_ccb = (dhcp_ccb_t *)ptr;
		if (dhcp_ccb) {
    		strcpy(sstr,DHCP_state2str(dhcp_ccb->lan_user_info[dhcp_ccb->cur_lan_user_index].state));
    		sprintf(buf,"dhcpd> ip pool index, user index[%u, %u, %s] ", dhcp_ccb->cur_ip_pool_index, dhcp_ccb->cur_lan_user_index, sstr);
    	}
		else
			sprintf(buf,"dhcpd> ");
	}

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


/*-------------------------------------------------------------------
 * DHCP_state2str
 *
 * input : state
 * return: string of corresponding state value
 *------------------------------------------------------------------*/
char *DHCP_state2str(U16 state)
{
	static struct {
		DHCP_STATE	state;
		char		str[20];
	} dhcp_state_desc_tbl[] = {
    	{ S_DHCP_INIT,  		"DHCP INIT" },
    	{ S_DHCP_DISCOVER_RECV, "DHCP DISCOVERY RECV" },
    	{ S_DHCP_OFFER_SENT,  	"DHCP OFFER SENT" },
    	{ S_DHCP_REQUEST_RECV,	"DHCP REQUEST RECV" },
    	{ S_DHCP_ACK_SENT,  	"DHCP ACK SENT" },
    	{ S_DHCP_NAK_SENT,		"DHCP NAK SENT" },
    	{ S_DHCP_INVLD,  		"DHCP INVALID" },
	};

	U8  i;
	
	for(i=0; dhcp_state_desc_tbl[i].state != S_DHCP_INVLD; i++) {
		if (dhcp_state_desc_tbl[i].state == state)  break;
	}
	if (dhcp_state_desc_tbl[i].state == S_DHCP_INVLD)
		return NULL;

	return dhcp_state_desc_tbl[i].str;
}