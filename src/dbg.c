/**************************************************************************
 * DBG.C
 *
 * Debug methods for ppp detection
 *
 * Created by THE on JUN 11,'19
 **************************************************************************/

#include    <common.h>
#include 	<rte_byteorder.h>
#include	"pppd/pppd.h"
#include 	"pppd/fsm.h"
#include 	"dhcpd/dhcp_fsm.h"
#include    "dbg.h"

#define 	DBG_VRG_MSG_LEN 256
#define 	LOGGER_BUF_LEN 1024

static VRG_t *vrg_ccb;

char *loglvl2str(U8 level)
{
    switch (level) {
    case LOGDBG:
        return "DBG";
    case LOGINFO:
        return "INFO";
	case LOGWARN:
        return "WARN";
    case LOGERR:
        return "ERR";
    default:
        return "UNKNOWN";
    }
}

U8 logstr2lvl(const char *log_str)
{
	if (strcmp(log_str, "DBG") == 0) {
		return LOGDBG;
	}
	if (strcmp(log_str, "INFO") == 0) {
		return LOGINFO;
	}
	if (strcmp(log_str, "WARN") == 0) {
		return LOGWARN;
	}
	if (strcmp(log_str, "ERR") == 0) {
		return LOGERR;
	}

	return LOGUNKNOWN;
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
    	{ S_INIT,  			"INIT" },
    	{ S_STARTING,  		"STARTING" },
    	{ S_CLOSED,  		"CLOSED" },
    	{ S_STOPPED,		"STOPPED" },
    	{ S_CLOSING,  		"CLOSING" },
    	{ S_STOPPING,		"STOPPONG" },
    	{ S_REQUEST_SENT,  	"REQUEST_SENT" },
    	{ S_ACK_RECEIVED,  	"ACK_RECEIVED" },
    	{ S_ACK_SENT,		"ACK_SENT" },
    	{ S_OPENED,  		"OPENED" },
    	{ S_INVLD,			"Unknwn" },
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
 * PPP_event2str
 *
 * input : event
 * return: string of corresponding event value
 *------------------------------------------------------------------*/
char *PPP_event2str(U16 event)
{
	static struct {
		PPP_EVENT_TYPE	event;
		char			str[64];
	} ppp_event_desc_tbl[] = {
		{ E_UP,  			"UP" },
		{ E_DOWN,  			"DOWN" },
		{ E_OPEN,  			"OPEN" },
		{ E_CLOSE,			"CLOSE" },
    	{ E_TIMEOUT_COUNTER_POSITIVE, "TIMEOUT_COUNTER_POSITIVE" },
    	{ E_TIMEOUT_COUNTER_EXPIRED,  "TIMEOUT_COUNTER_EXPIRED" },
    	{ E_RECV_GOOD_CONFIG_REQUEST, "RECV_GOOD_CONFIG_REQUEST" },
    	{ E_RECV_BAD_CONFIG_REQUEST,  "RECV_BAD_CONFIG_REQUEST" },
    	{ E_RECV_CONFIG_ACK,		  "RECV_CONFIG_ACK" },
    	{ E_RECV_CONFIG_NAK_REJ,  	  "RECV_CONFIG_NAK_REJECT" },
    	{ E_RECV_TERMINATE_REQUEST,	  "RECV_TERMINATE_REQUEST" },
		{ E_RECV_TERMINATE_ACK,  	  "RECV_TERMINATE_ACK" },
    	{ E_RECV_UNKNOWN_CODE,  	  "RECV_UNKNOWN_CODE" },
    	{ E_RECV_GOOD_CODE_PROTOCOL_REJECT,	"RECV_GOOD_CODE_PROTOCOL_REJECT" },
    	{ E_RECV_BAD_CODE_PROTOCOL_REJECT,  "RECV_BAD_CODE_PROTOCOL_REJECT" },
    	{ E_RECV_ECHO_REPLY_REQUEST_DISCARD_REQUEST, "RECV_ECHO_REPLY_REQUEST_DISCARD_REQUEST" },
		{ E_UNKNOWN,  		"UNKNOWN" },
	};

	U8  i;
	
	for(i=0; ppp_event_desc_tbl[i].event != E_UNKNOWN; i++) {
		if (ppp_event_desc_tbl[i].event == event)  break;
	}

	return ppp_event_desc_tbl[i].str;
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

void PPPLOGMSG(void *ccb, char *buf)
{
	PPP_INFO_t *s_ppp_ccb = (PPP_INFO_t *)ccb;
    if (s_ppp_ccb) {
    	sprintf(buf, "pppd> Session id [%x] ", rte_be_to_cpu_16(s_ppp_ccb->session_id));
	}
}

void DHCPLOGMSG(void *ccb, char *buf)
{
	dhcp_ccb_t *dhcp_ccb = (dhcp_ccb_t *)ccb;
	if (dhcp_ccb) {
    	sprintf(buf,"dhcpd> ip pool index, user index[%u, %u, %s] ", dhcp_ccb->cur_ip_pool_index, dhcp_ccb->cur_lan_user_index, DHCP_state2str(dhcp_ccb->lan_user_info[dhcp_ccb->cur_lan_user_index].state));
    }
}

/***************************************************
 * LOGGER:
 ***************************************************/	
void LOGGER(U8 level, char *filename, int line_num, FILE *log_fp, void *ccb, void (*ccb2str)(void *, char *), const char *fmt,...)
{
	va_list ap; /* points to each unnamed arg in turn */
	char    buf[LOGGER_BUF_LEN], protocol_buf[LOGGER_BUF_LEN-100], msg[DBG_VRG_MSG_LEN];
	
	protocol_buf[0] = '\0';
	msg[0] = 0;
	buf[0] = 0;

	//user offer level must > system requirement
    if (vrg_ccb->loglvl > level)
		return;
	
	va_start(ap, fmt); /* set ap pointer to 1st unnamed arg */
    vsnprintf(msg, DBG_VRG_MSG_LEN, fmt, ap);

	if (ccb2str)
		ccb2str(ccb, protocol_buf);

	snprintf(buf, sizeof(buf)-1, "vRG[%s]: %s:%d> %s", loglvl2str(level), filename, line_num, protocol_buf);
	strncat(buf, msg, sizeof(buf)-1);
    va_end(ap);
	
	buf[sizeof(buf)-1] = '\0';
	if (vrg_ccb->loglvl == LOGDBG)
		fprintf(stdout, "%s\n", buf);
	if (log_fp != NULL) {
        fwrite(buf, sizeof(char), strlen(buf), log_fp);
        char *newline = "\n";
        fwrite(newline, sizeof(char), strlen(newline), log_fp);
        fflush(log_fp);
    }
}

void dbg_init(void *ccb)
{
	vrg_ccb = (VRG_t *)ccb;
}
