/*\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\
  PPPD.H

     For ppp detection

  Designed by THE on Jan 14, 2019
/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\*/

#ifndef _PPPD_H_
#define _PPPD_H_

#include <common.h>
#include <rte_timer.h>
#include <rte_memory.h>

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

#define MAX_USER				2

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

typedef struct pppoe_header {
	uint8_t ver_type;
	uint8_t code;
	uint16_t session_id;
	uint16_t length;
} pppoe_header_t;

typedef struct pppoe_header_tag {
	uint16_t type;
  	uint16_t length;
  	// depend on the type and length.
  	uint8_t value[0];
} pppoe_header_tag_t;

typedef struct ppp_lcp_header {
	uint8_t code;
	uint8_t identifier;
	uint16_t length;
}ppp_lcp_header_t;

typedef struct ppp_pap_ack_nak {
	uint8_t msg_length;
	uint8_t msg[0];
}ppp_pap_ack_nak_t;

typedef struct ppp_payload {
	uint16_t ppp_protocol;
}ppp_payload_t;

typedef struct ppp_lcp_options {
	uint8_t type;
	uint8_t length;
	uint8_t val[0];
}ppp_lcp_options_t;

typedef struct pppoe_phase {
	struct ethhdr 		*eth_hdr;
	pppoe_header_t 		*pppoe_header;
	pppoe_header_tag_t	*pppoe_header_tag;
	uint8_t 			max_retransmit;
	uint8_t				timer_counter;
}pppoe_phase_t;

typedef struct ppp_phase {
	U8 					state;
	struct ethhdr 		*eth_hdr;
	pppoe_header_t 		*pppoe_header;
	ppp_payload_t 		*ppp_payload;
	ppp_lcp_header_t 	*ppp_lcp;
	ppp_lcp_options_t 	*ppp_lcp_options;
	uint8_t 			max_retransmit;
	uint8_t				timer_counter;
}ppp_phase_t;

typedef struct addr_table {
	unsigned char 	mac_addr[6];
	uint32_t		src_ip;
	uint32_t		dst_ip;
	uint16_t		port_id;
	uint32_t		shift;
	int8_t 			is_fill;
	uint8_t			is_alive;
}__rte_cache_aligned addr_table_t;

//========= The structure of port ===========
typedef struct {
	BOOL				enable;
	U8					query_cnt;
	U16					port;

	U32					imsg_cnt;
	U32					omsg_cnt;
	U32					err_imsg_cnt;
	
	tSUB_VAL			chassis_id;
	tSUB_VAL			port_id;
		
	U32					ttl;
	char				port_desc[80];
	char				sys_name[80];
	char				sys_desc[255];
	
	tSYS_CAP			sys_cap;
	tMNG_ADDR  			mng_addr;

	ppp_phase_t 		ppp_phase[2];
	pppoe_phase_t		pppoe_phase;
	int 				cp;	//cp is "control protocol", means we need to determine cp is LCP or NCP after parsing packet
	uint16_t 			session_id;
	uint16_t			user_num;
	uint8_t				phase;

	unsigned char 		src_mac[6];
	unsigned char 		dst_mac[6];
	unsigned char 		lan_mac[6];

	uint32_t    		ipv4;
	uint32_t			ipv4_gw;
	uint32_t			primary_dns;
	uint32_t			second_dns;

	uint8_t				identifier;
	uint32_t			magic_num;

	BOOL				is_pap_auth;
	unsigned char 		*user_id;
	unsigned char 		*passwd;

	BOOL				data_plane_start;

	uint8_t 			vlan;

	addr_table_t 		addr_table[65536];

	struct rte_timer 	pppoe;
	struct rte_timer 	ppp;
	struct rte_timer 	nat;
}__rte_cache_aligned tPPP_PORT;

extern tPPP_PORT		ppp_ports[MAX_USER];
extern U32				ppp_interval;
extern U8				ppp_max_msg_per_query;

int 				ppp_init(void);

int 				pppdInit(void);
void 				PPP_bye(void);
void 				PPP_int(void);
int 				control_plane(void);

/*-----------------------------------------
 * Queue between IF driver and daemon
 *----------------------------------------*/
typedef struct {
	U16  			type;
	U8          	refp[ETH_MTU];
	int	        	len;
} tPPP_MBX;

#endif