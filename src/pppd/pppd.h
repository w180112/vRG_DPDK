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
#include "header.h"

#define MULTICAST_TAG 			4001
#define TOTAL_SOCK_PORT			65536

/**
 * @brief hsi nat table structure
 */
typedef struct addr_table {
	struct rte_ether_addr 	mac_addr;
	U32						src_ip;
	U32						dst_ip;
	U16						port_id;
	rte_atomic16_t 			is_fill;
	rte_atomic16_t			is_alive;
}__rte_cache_aligned addr_table_t;

/**
 * @brief hsi control block structure
 */
typedef struct {
	U16						user_num;		/* subscriptor id */
	U16 					vlan;			/* subscriptor vlan */
	struct rte_ether_hdr 	eth_hdr;
	vlan_header_t			vlan_header __rte_aligned(sizeof(vlan_header_t));
	pppoe_header_t 			pppoe_header __rte_aligned(sizeof(vlan_header_t));
    ppp_phase_t 			ppp_phase[2];	/* store lcp and ipcp info, index 0 means lcp, index 1 means ipcp */
	pppoe_phase_t			pppoe_phase;	/* store pppoe info */
	U8 						cp:1;			/* cp is "control protocol", means we need to determine cp is LCP or NCP after parsing packet */
	U8						phase:7;		/* pppoe connection phase */
	U16 					session_id;		/* pppoe session id */
    struct rte_ether_addr 	PPP_dst_mac;	/* pppoe server mac addr */
    U32    					hsi_ipv4;		/* ip addr pppoe server assign to pppoe client */
	U32						hsi_ipv4_gw;	/* ip addr gateway pppoe server assign to pppoe client */
	U32						hsi_primary_dns;/* 1st dns addr pppoe server assign to pppoe client */
	U32						hsi_second_dns;	/* 2nd dns addr pppoe server assign to pppoe client */
    U8						identifier;		/* ppp pkt id */
	U32						magic_num;		/* ppp pkt magic number, in network order */
    BOOL					is_pap_auth;	/* pap auth boolean flag */
    U16 					auth_method;	/* use chap or pap */
	U8 						*ppp_user_id;	/* pap/chap account */
	U8 						*ppp_passwd;	/* pap/chap password */
    rte_atomic16_t 			ppp_bool; 		/* boolean flag for accept ppp packets at data plane */
    rte_atomic16_t 			dp_start_bool;	/* hsi data plane starting boolean flag */
    BOOL					ppp_processing; /* boolean flag for checking ppp is disconnecting */
	//FILE 					*fp;			/* log file pointer */
    addr_table_t 			addr_table[TOTAL_SOCK_PORT]; /* hsi nat addr table */
    struct rte_timer 	    pppoe;			/* pppoe timer */
	struct rte_timer 	    ppp;			/* ppp timer */
	struct rte_timer 	    nat;			/* nat table timer */
    struct rte_timer 	    ppp_alive; 		/* PPP connection checking timer */
}__rte_cache_aligned PPP_INFO_t;

extern U32	ppp_interval;

void 		PPP_int(void);
void 		exit_ppp(__attribute__((unused)) struct rte_timer *tim, PPP_INFO_t *ppp_ccb);
STATUS 		ppp_process(void *mail);
STATUS 		ppp_connect(PPP_INFO_t *ppp_ccb, U16 user_id);
STATUS 		ppp_disconnect(PPP_INFO_t *ppp_ccb, U16 user_id);
STATUS 		pppdInit(void *ccb);
void 		PPP_bye(PPP_INFO_t *ppp_ccb);

#endif