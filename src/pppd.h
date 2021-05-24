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
#include <rte_ether.h>

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

#define MULTICAST_TAG 			4001

#define MAX_USER				2

#define BASE_VLAN_ID			2

#define MLX5					1
#define IXGBE					2
#define I40E					3
#define VMXNET3					4
#define IXGBEVF					5
#define I40EVF					6

#define TOTAL_SOCK_PORT			65536

enum {
	CTRL_LCORE = 1,
	WAN_LCORE,
	DOWNLINK_LCORE,
	LAN_LCORE,
	UPLINK_LCORE,
	GATEWAY_LCORE,
	TIMER_LOOP_LCORE,
};

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

/* VLAN header structure definition.
 * We use bit feild here, but bit field order is uncertain.
 * It depends on compiler implementation.
 * In GCC, bit field is bind with endianess.
 * https://rednaxelafx.iteye.com/blog/257760
 * http://www.programmer-club.com.tw/ShowSameTitleN/general/6887.html
 * http://pl-learning-blog.logdown.com/posts/1077056-usually-terror-words-o-muhammad-c-ch13-reading-notes-unfinished
 */
typedef struct vlan_header {
	union tci_header {
		U16 tci_value;
		struct tci_bit {
			#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
			U16 vlan_id:12;
			U16 DEI:1;
			U16 priority:3;
			#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
			U16 priority:3;
			U16 DEI:1;
			U16 vlan_id:12;
			#endif
		}tci_struct;
	}tci_union;
	U16 next_proto;
}__rte_aligned(2) vlan_header_t;

typedef struct pppoe_header {
	U8 ver_type;
	U8 code;
	U16 session_id;
	U16 length;
} pppoe_header_t;

typedef struct pppoe_header_tag {
	U16 type;
  	U16 length;
  	// depend on the type and length.
  	U8 value[0];
} pppoe_header_tag_t;

typedef struct ppp_header {
	U8 code;
	U8 identifier;
	U16 length;
}ppp_header_t;

typedef struct ppp_pap_ack_nak {
	U8 msg_length;
	U8 *msg;
}ppp_pap_ack_nak_t;

typedef struct ppp_payload {
	U16 ppp_protocol;
}ppp_payload_t;

typedef struct ppp_options {
	U8 type;
	U8 length;
	U8 val[0];
}ppp_options_t;

typedef struct pppoe_phase {
	struct rte_ether_hdr *eth_hdr;
	vlan_header_t		*vlan_header;
	pppoe_header_t 		*pppoe_header;
	pppoe_header_tag_t	*pppoe_header_tag;
	U8 					max_retransmit;
	U8					timer_counter;
	BOOL 				active;
}pppoe_phase_t;

typedef struct ppp_phase {
	U8 					state;
	struct rte_ether_hdr *eth_hdr;
	vlan_header_t		*vlan_header;
	pppoe_header_t 		*pppoe_header;
	ppp_payload_t 		*ppp_payload;
	ppp_header_t 		*ppp_hdr;
	ppp_options_t 		*ppp_options;
	U8 					max_retransmit;
	U8					timer_counter;
}ppp_phase_t;

typedef struct addr_table {
	struct rte_ether_addr 	mac_addr;
	U32						src_ip;
	U32						dst_ip;
	U16						port_id;
	rte_atomic16_t 			is_fill;
	rte_atomic16_t			is_alive;
}__rte_cache_aligned addr_table_t;

//========= The structure of port ===========
typedef struct {
	ppp_phase_t 			ppp_phase[2];
	pppoe_phase_t			pppoe_phase;
	U8 						cp:1;	//cp is "control protocol", means we need to determine cp is LCP or NCP after parsing packet
	U8						phase:7;
	U16 					session_id;
	U16						user_num;
	U16 					vlan;
	U32						lan_ip;

	struct rte_ether_addr 	src_mac;
	struct rte_ether_addr 	dst_mac;
	struct rte_ether_addr 	lan_mac;

	U32    					ipv4;
	U32						ipv4_gw;
	U32						primary_dns;
	U32						second_dns;

	U8						identifier;
	U32						magic_num;

	BOOL					is_pap_auth;
	unsigned char 			*user_id;
	unsigned char 			*passwd;
	rte_atomic16_t 			dhcp_bool; //boolean value for accept dhcp packets at data plane
	rte_atomic16_t 			ppp_bool; //boolean value for accept ppp packets at data plane
	BOOL					data_plane_start;
	BOOL					ppp_processing; //boolean value for checking ppp is disconnecting

	addr_table_t 		addr_table[TOTAL_SOCK_PORT];

	struct rte_timer 	pppoe;
	struct rte_timer 	ppp;
	struct rte_timer 	nat;
	struct rte_timer 	link;
}__rte_cache_aligned tPPP_PORT;

extern tPPP_PORT		ppp_ports[MAX_USER];
extern U32				ppp_interval;
extern U8				ppp_max_msg_per_query;

extern void 		PPP_int(void);

int 				ppp_init(void);
int 				pppdInit(void);
void 				PPP_bye(tPPP_PORT *port_ccb);
void 				PPP_ter(void);
int 				control_plane(void);

/*-----------------------------------------
 * Queue between IF driver and daemon
 *----------------------------------------*/
typedef struct {
	U16  			type;
	U8          	refp[ETH_MTU];
	int	        	len;
} tPPP_MBX;

extern tPPP_PORT	ppp_ports[MAX_USER];

#endif