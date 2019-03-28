/*\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\
  PPPD.H

     For ppp detection

  Designed by THE on Jan 14, 2019
/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\*/
#include <common.h>

#define ETH_MTU					1500
#define TEST_PORT_ID			1

#define	MIN_FRAME_SIZE			64
#define	MAX_QUE_EVT_CNT			(MBOX_QUE_SIZE/2)
#define _PBM(port)				(1<<(port-1))

#define MAX_USER_PORT_NUM		44
#define MAX_PPP_QUERY_NUM		1
#define DEF_QUERY_INTERVAL		2

#define FWD_STD_802_1Q			1
#define FWD_REFLECTIVE_RELAY	1
#define CAP_VSI_DISCOV_PROTO	1
#define CAP_802_1X_AUTH_REQ		1

typedef struct {
	U8		subt;
	U16		len;
	U8		value[255];
} tSUB_VAL;

//========= system capability ===========
typedef struct {
	U16		cap_map;
	U16		en_map;
} tSYS_CAP;

//========= management address ===========
typedef struct {
	U8		addr_strlen; //addr_subt + addr[]
	U8		addr_subt;
	U8		addr[31];
	
	U8		if_subt;
	U32		if_no;
	
	U8		oid_len;
	U32		oids[128];
} tMNG_ADDR;

//========= The structure of port ===========
typedef struct {
	BOOL		enable;
	U8 			state;
	U8			query_cnt;
	U16			port;

	U32			imsg_cnt;
	U32			omsg_cnt;
	U32			err_imsg_cnt;	
	
	tSUB_VAL	chassis_id;
	tSUB_VAL	port_id;
		
	U32			ttl;
	char		port_desc[80];
	char		sys_name[80];
	char		sys_desc[255];
	
	tSYS_CAP	sys_cap;
	tMNG_ADDR  	mng_addr;
} tPPP_PORT;

extern U8	 			g_loc_mac[]; //system mac addr -- global variable
extern tPPP_PORT		ppp_ports[2];
extern tIPC_ID 			pppQid;
extern tIPC_ID 			pppQid_main;
extern U32				ppp_interval;
extern U8				ppp_max_msg_per_query;

extern void 		PPP_save_imsg(/*tPPP_MSG *imsg*/);
int 				ppp_init(void);

int pppdInit(void);
void PPP_bye(void);
int control_plane(void);

/*-----------------------------------------
 * Queue between IF driver and daemon
 *----------------------------------------*/
typedef struct {
	U16  			type;
	U8          	refp[ETH_MTU];
	int	        	len;
} tPPP_MBX;
