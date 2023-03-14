#ifndef _PPPOECLIENT_H_
#define _PPPOECLIENT_H_

#include <time.h>
#include <sys/wait.h>
#include "pppd.h"
#include <common.h>

#define ETH_P_PPP_DIS 		0x8863
#define ETH_P_PPP_SES		0x8864
#define VLAN                0x8100

#define PPPOE_PHASE			0x1
#define LCP_PHASE			0x2
#define AUTH_PHASE			0x3
#define IPCP_PHASE			0x4
#define DATA_PHASE			0x5
#define END_PHASE			0x0

#define END_OF_LIST 		0x0
#define SERVICE_NAME 		0x0101
#define AC_NAME 			0x0102
#define HOST_UNIQ 			0x0103
#define AC_COOKIE 			0x0104
#define VENDER_SPECIFIC 	0x0105
#define RELAY_ID 			0x0110
#define SERVICE_NAME_ERROR 	0x0201
#define AC_SYSTEM_ERROR 	0x0202
#define GENERIC_ERROR 		0x0203

#define VER_TYPE 			0x11
#define PADI 				0x9
#define PADO 				0x7
#define PADR 				0x19
#define PADS 				0x65
#define PADT 				0xa7
#define PADM				0xd3
#define SESSION_DATA 		0x0

#define LCP_PROTOCOL 		0xc021
#define IP_PROTOCOL 		0x0021
#define IPCP_PROTOCOL		0x8021
#define PAP_PROTOCOL		0xc023
#define CHAP_PROTOCOL		0xc223

/* define for LCP/IPCP code */
#define CONFIG_REQUEST 		0x1
#define CONFIG_ACK 			0x2
#define CONFIG_NAK			0x3
#define CONFIG_REJECT		0x4
#define TERMIN_REQUEST		0x5
#define TERMIN_ACK			0x6
#define CODE_REJECT			0x7
#define PROTO_REJECT		0x8
#define ECHO_REQUEST 		0x9
#define ECHO_REPLY			0xa

#define PAP_REQUEST		    0x1
#define PAP_ACK			    0x2
#define PAP_NAK			    0x3

#define CHAP_CHALLANGE      0x1
#define CHAP_RESPONSE       0x2
#define CHAP_SUCCESS        0x3
#define CHAP_FAILURE        0x4

/* define for LCP options */
#define MAGIC_NUM			0x5
#define MRU					0x1
#define AUTH				0x3

/* define for IPCP options */
#define IP_ADDRESSES		0x1
#define	IP_COMPRESSION		0x2
#define	IP_ADDRESS 			0x3
#define PRIMARY_DNS			0x81
#define SECOND_DNS			0x83

#define MAX_RECV			ETH_MTU - sizeof(pppoe_header_t) - sizeof(ppp_payload_t) - sizeof(vlan_header_t)
#define MAX_RETRAN			10

#endif