/*\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\
  DHCP_CODEC.H

  Designed by THE on MAR 21, 2021
/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\*/

#ifndef _DHCP_CODEC_H_
#define _DHCP_CODEC_H_

#include <common.h>
#include <rte_udp.h>
#include <rte_timer.h>
#include <rte_ether.h>
#include "protocol.h"

#define MAX_IP_POOL 100
#define LAN_USER MAX_IP_POOL
#define LEASE_TIMEOUT 3600

typedef struct dhcp_info dhcp_info_t;

typedef struct ip_pool {
    struct rte_ether_addr mac_addr;
    U32 ip_addr;
    BOOL used;
}ip_pool_t;

typedef struct lan_user_info {
    U8 					    state;
    U32                     timer_counter;
    BOOL                    lan_user_used;
    struct rte_ether_addr   mac_addr;
    struct rte_timer        timer;
    struct rte_timer        lan_user_timer;
}lan_user_info_t;

typedef struct dhcp_ccb { 
    dhcp_info_t             *dhcp_info;
    struct rte_ether_hdr    *eth_hdr;
    vlan_header_t           *vlan_hdr;
    struct rte_ipv4_hdr     *ip_hdr;
    struct rte_udp_hdr      *udp_hdr;
    U32                     dhcp_server_ip;
    U8                      cur_lan_user_index;
    U8                      cur_ip_pool_index;
    ip_pool_t               ip_pool[MAX_IP_POOL];
    lan_user_info_t         lan_user_info[LAN_USER];
    rte_atomic16_t 			dhcp_bool; //boolean value for accept dhcp packets at data plane
}dhcp_ccb_t;

BIT16 dhcp_decode(dhcp_ccb_t *dhcp_ccb, struct rte_ether_hdr *eth_hdr, vlan_header_t *vlan_header, struct rte_ipv4_hdr *ip_hdr, struct rte_udp_hdr *udp_hdr);

#define DHCP_SUBNET_MASK 1
#define DHCP_ROUTER 3
#define DHCP_DNS 6
#define DHCP_HOSTNAME 12
#define DHCP_REQUEST_IP 50
#define DHCP_LEASE_TIME 51
#define DHCP_MSG_TYPE 53
#define DHCP_SERVER_ID 54
#define DHCP_PARAMETER_LIST 55
#define DHCP_RENEWAL_VAL 58
#define DHCP_REBIND_TIME_VAL 59
#define DHCP_ISP_ID 60
#define DHCP_CLIENT_ID 61
#define DHCP_END 255

enum {
    DHCP_DISCOVER = 1,
    DHCP_OFFER,
    DHCP_REQUEST,
    DHCP_DECLINE,
    DHCP_ACK,
    DHCP_NAK,
    DHCP_RELEASE,
    DHCP_INFORM,
    DHCP_FORCE_RENEW,
    DHCP_LEASE_QUERY,
    DHCP_LEASE_UNASSIGNED,
    DHCP_LEASE_UNKNOWN,
    DHCP_LEASE_ACTIVE,
};

#endif