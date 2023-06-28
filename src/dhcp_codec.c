#include <stdint.h>
#include <common.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_byteorder.h>
#include "dhcp_fsm.h"

typedef struct dhcp_opt {
    U8 opt_type;
    U8 len;
    U8 val[0];
}dhcp_opt_t;

typedef struct dhcp_info {
    U8 msg_type;
    U8 hwr_type;
    U8 hwr_addr_len;
    U8 hops;
    U32 transaction_id;
    U16 sec_elapsed;
    U16 bootp_flag;
    U32 client_ip;
    U32 ur_client_ip;
    U32 next_server_ip;
    U32 relay_agent_ip;
    struct rte_ether_addr mac_addr;
    unsigned char mac_addr_padding[10];
    unsigned char server_name[64];
    unsigned char file_name[128];
    U32 magic_cookie;
    dhcp_opt_t opt_ptr[0];
}dhcp_info_t;

STATUS decode_request(dhcp_ccb_t *dhcp_ccb);
STATUS check_pool(dhcp_ccb_t *dhcp_ccb, struct rte_ether_addr mac_addr);
static U16 ip_hdr_id = 1;

BIT16 dhcp_decode(dhcp_ccb_t *dhcp_ccb, struct rte_ether_hdr *eth_hdr, vlan_header_t *vlan_header, struct rte_ipv4_hdr *ip_hdr, struct rte_udp_hdr *udp_hdr)
{
    dhcp_opt_t *cur; 
    BIT16 event = -1;

    dhcp_ccb->eth_hdr = eth_hdr;
    dhcp_ccb->vlan_hdr = vlan_header;
    dhcp_ccb->ip_hdr = ip_hdr;
    dhcp_ccb->udp_hdr = udp_hdr;
    dhcp_ccb->dhcp_info = (dhcp_info_t *)(udp_hdr + 1);
    cur = (dhcp_opt_t *)(dhcp_ccb->dhcp_info + 1);
    
    for(; cur->opt_type!=DHCP_END; cur=(dhcp_opt_t *)(((U8 *)(cur+1))+cur->len)) {
        if (cur->opt_type == DHCP_ISP_ID)
            return 0;
        else if (cur->opt_type == DHCP_MSG_TYPE) {
            switch (*(U8 *)(cur+1)) {
            case DHCP_DISCOVER:
                event = E_DISCOVER;
                break;
            case DHCP_REQUEST:
                if (decode_request(dhcp_ccb) == TRUE)
                    event = E_GOOD_REQUEST;
                else 
                    event = E_BAD_REQUEST;
                rte_timer_stop(&dhcp_ccb->lan_user_info[dhcp_ccb->cur_lan_user_index].timer);
                break;
            case DHCP_RELEASE:
                if (check_pool(dhcp_ccb, eth_hdr->src_addr))
                    event = E_RELEASE;
                break;
            default:
                break;
            }
        }
        else if (cur->opt_type == DHCP_HOSTNAME) {
        }
    }
    return event;
}

STATUS check_pool(dhcp_ccb_t *dhcp_ccb, struct rte_ether_addr mac_addr)
{
    U32 pool_index = (mac_addr.addr_bytes[0] + mac_addr.addr_bytes[1] + mac_addr.addr_bytes[2] + mac_addr.addr_bytes[3] + mac_addr.addr_bytes[4] + mac_addr.addr_bytes[5]) % MAX_IP_POOL;
    int i;
    
    for(i=pool_index; i<MAX_IP_POOL; i++) {
        if (dhcp_ccb->ip_pool[i].used == FALSE) {
            dhcp_ccb->cur_ip_pool_index = i;
            dhcp_ccb->ip_pool[i].used = TRUE;
            return TRUE;
        }
        else if (rte_is_same_ether_addr(&mac_addr, &dhcp_ccb->ip_pool[i].mac_addr)) {
            dhcp_ccb->cur_ip_pool_index = i;
            return TRUE;
        }
    }
    for(int j=0; j<i; j++) {
        if (dhcp_ccb->ip_pool[j].used == FALSE) {
            dhcp_ccb->cur_ip_pool_index = j;
            dhcp_ccb->ip_pool[j].used = TRUE;
            return TRUE;
        }
        else if (rte_is_same_ether_addr(&mac_addr, &dhcp_ccb->ip_pool[j].mac_addr)) {
            dhcp_ccb->cur_ip_pool_index = j;
            return TRUE;
        }
    }

    return FALSE;
}

STATUS decode_request(dhcp_ccb_t *dhcp_ccb)
{
    dhcp_opt_t *opt_ptr = (dhcp_opt_t *)(dhcp_ccb->dhcp_info + 1);
    dhcp_opt_t *cur = opt_ptr;
    struct rte_ether_addr mac_addr;
    
    rte_ether_addr_copy(&dhcp_ccb->eth_hdr->src_addr, &mac_addr);
    if (dhcp_ccb->dhcp_info->client_ip | RTE_IPV4_ANY) {
        dhcp_ccb->dhcp_info->ur_client_ip = dhcp_ccb->dhcp_info->client_ip;
        dhcp_ccb->dhcp_info->client_ip = 0;
    }
    else {
        for(; cur->opt_type!=DHCP_END; cur=(dhcp_opt_t *)(((U8 *)(cur+1))+cur->len)) {
            /*if (cur->opt_type == DHCP_CLIENT_ID)
                rte_ether_addr_copy((struct rte_ether_addr *)(cur->val), &mac_addr);
            else */if (cur->opt_type == DHCP_REQUEST_IP)
                rte_memcpy(&dhcp_ccb->dhcp_info->ur_client_ip, cur->val, 4);
        }
    }

    return check_pool(dhcp_ccb, mac_addr);
}

int pick_ip_from_pool(dhcp_ccb_t *dhcp_ccb, U32 *ip_addr, struct rte_ether_addr mac_addr)
{
    U32 pool_index = (mac_addr.addr_bytes[0] + mac_addr.addr_bytes[1] + mac_addr.addr_bytes[2] + mac_addr.addr_bytes[3] + mac_addr.addr_bytes[4] + mac_addr.addr_bytes[5]) % MAX_IP_POOL;
    int i;
    
    for(i=pool_index; i<MAX_IP_POOL; i++) {
        if (dhcp_ccb->ip_pool[i].used == FALSE) {
            *ip_addr = dhcp_ccb->ip_pool[i].ip_addr;
            rte_ether_addr_copy(&mac_addr, &dhcp_ccb->ip_pool[i].mac_addr);
            dhcp_ccb->cur_ip_pool_index = i;
            return 0;
        }
    }
    for(int j=0; j<i; j++) {
        if (dhcp_ccb->ip_pool[j].used == FALSE) {
            *ip_addr = dhcp_ccb->ip_pool[j].ip_addr;
            rte_ether_addr_copy(&mac_addr, &dhcp_ccb->ip_pool[j].mac_addr);
            dhcp_ccb->cur_ip_pool_index = j;
            return 0;
        }
    }
    return -1;
}

STATUS build_dhcp_offer(dhcp_ccb_t *dhcp_ccb)
{
    struct rte_ether_addr macaddr;
    U32 ip_addr;

    rte_eth_macaddr_get(0, &macaddr);
    rte_ether_addr_copy(&dhcp_ccb->eth_hdr->src_addr, &dhcp_ccb->eth_hdr->dst_addr);
    rte_ether_addr_copy(&macaddr, &dhcp_ccb->eth_hdr->src_addr);
    if (pick_ip_from_pool(dhcp_ccb, &ip_addr, dhcp_ccb->eth_hdr->dst_addr) < 0)
        return FALSE;
    dhcp_ccb->ip_hdr->packet_id = ip_hdr_id++;
    dhcp_ccb->ip_hdr->packet_id = rte_cpu_to_be_16(dhcp_ccb->ip_hdr->packet_id);
    dhcp_ccb->ip_hdr->hdr_checksum = 0;
    dhcp_ccb->ip_hdr->src_addr = dhcp_ccb->dhcp_server_ip;
    dhcp_ccb->ip_hdr->dst_addr = ip_addr;
    dhcp_ccb->ip_hdr->total_length = (U16)sizeof(struct rte_ipv4_hdr);

    dhcp_ccb->udp_hdr->src_port = rte_cpu_to_be_16(67);
    dhcp_ccb->udp_hdr->dst_port = rte_cpu_to_be_16(68);
    dhcp_ccb->udp_hdr->dgram_cksum = 0;
    dhcp_ccb->udp_hdr->dgram_len = sizeof(struct rte_udp_hdr);

    dhcp_ccb->dhcp_info->msg_type = 0x2;
    dhcp_ccb->dhcp_info->ur_client_ip = ip_addr;
    dhcp_ccb->dhcp_info->next_server_ip = dhcp_ccb->dhcp_server_ip;
    dhcp_ccb->udp_hdr->dgram_len += sizeof(dhcp_info_t);

    unsigned char buf[64];

    dhcp_opt_t *cur = (dhcp_opt_t *)buf;
    cur->opt_type = DHCP_MSG_TYPE;
    cur->len = 0x1;
    *(cur->val) = DHCP_OFFER;
    dhcp_ccb->udp_hdr->dgram_len += sizeof(dhcp_opt_t) + cur->len;

    cur = (dhcp_opt_t *)(((char *)cur) + sizeof(dhcp_opt_t) + cur->len);
    cur->opt_type = DHCP_SERVER_ID;
    cur->len = 0x4;
    rte_memcpy(cur->val, &dhcp_ccb->dhcp_server_ip, cur->len);
    dhcp_ccb->udp_hdr->dgram_len += sizeof(dhcp_opt_t) + cur->len;

    cur = (dhcp_opt_t *)(((char *)cur) + sizeof(dhcp_opt_t) + cur->len);
    cur->opt_type = DHCP_SUBNET_MASK;
    cur->len = 0x4;
    cur->val[0] = 0x00;
    cur->val[1] = cur->val[2] = cur->val[3] = 0xff;
    dhcp_ccb->udp_hdr->dgram_len += sizeof(dhcp_opt_t) + cur->len;

    cur = (dhcp_opt_t *)(((char *)cur) + sizeof(dhcp_opt_t) + cur->len);
    cur->opt_type = DHCP_LEASE_TIME;
    cur->len = 0x4;
    U32 lease_time = rte_cpu_to_be_32(LEASE_TIMEOUT); //1 hr
    rte_memcpy(cur->val, &lease_time, cur->len);
    dhcp_ccb->udp_hdr->dgram_len += sizeof(dhcp_opt_t) + cur->len;

    cur = (dhcp_opt_t *)(((char *)cur) + sizeof(dhcp_opt_t) + cur->len);
    cur->opt_type = DHCP_ROUTER;
    cur->len = 0x4;
    rte_memcpy(cur->val, &dhcp_ccb->dhcp_server_ip, cur->len);
    dhcp_ccb->udp_hdr->dgram_len += sizeof(dhcp_opt_t) + cur->len;
    
    cur = (dhcp_opt_t *)(((char *)cur) + sizeof(dhcp_opt_t) + cur->len);
    cur->opt_type = DHCP_DNS;
    cur->len = 0x8;
    U32 dns[2] = { rte_cpu_to_be_32(0x08080808), rte_cpu_to_be_32(0x01010101)};
    rte_memcpy(cur->val, &dns, cur->len);
    dhcp_ccb->udp_hdr->dgram_len += sizeof(dhcp_opt_t) + cur->len;

    cur = (dhcp_opt_t *)(((char *)cur) + sizeof(dhcp_opt_t) + cur->len);
    memset(cur, 0, 23);
    *(U8 *)cur = DHCP_END;
    dhcp_ccb->udp_hdr->dgram_len += 1 + 22;

    rte_memcpy((dhcp_ccb->dhcp_info + 1), buf, dhcp_ccb->udp_hdr->dgram_len);

    dhcp_ccb->ip_hdr->total_length += dhcp_ccb->udp_hdr->dgram_len;
    //PRINT_MESSAGE(dhcp_ccb->eth_hdr, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(vlan_header_t) + dhcp_ccb->ip_hdr->total_length);
    
    dhcp_ccb->udp_hdr->dgram_len = rte_cpu_to_be_16(dhcp_ccb->udp_hdr->dgram_len);
    dhcp_ccb->ip_hdr->total_length = rte_cpu_to_be_16(dhcp_ccb->ip_hdr->total_length);
    dhcp_ccb->ip_hdr->hdr_checksum = rte_ipv4_cksum(dhcp_ccb->ip_hdr);

    return TRUE;
}

STATUS build_dhcp_ack(dhcp_ccb_t *dhcp_ccb)
{
    struct rte_ether_addr macaddr;

    rte_eth_macaddr_get(0, &macaddr);
    rte_ether_addr_copy(&dhcp_ccb->eth_hdr->src_addr, &dhcp_ccb->eth_hdr->dst_addr);
    rte_ether_addr_copy(&macaddr, &dhcp_ccb->eth_hdr->src_addr);

    dhcp_ccb->ip_hdr->packet_id = ip_hdr_id++;
    dhcp_ccb->ip_hdr->packet_id = rte_cpu_to_be_16(dhcp_ccb->ip_hdr->packet_id);
    dhcp_ccb->ip_hdr->hdr_checksum = 0;
    dhcp_ccb->ip_hdr->src_addr = dhcp_ccb->dhcp_server_ip;
    dhcp_ccb->ip_hdr->dst_addr = dhcp_ccb->dhcp_info->ur_client_ip;
    dhcp_ccb->ip_hdr->total_length = sizeof(struct rte_ipv4_hdr);

    dhcp_ccb->udp_hdr->src_port = rte_cpu_to_be_16(67);
    dhcp_ccb->udp_hdr->dst_port = rte_cpu_to_be_16(68);
    dhcp_ccb->udp_hdr->dgram_cksum = 0;
    dhcp_ccb->udp_hdr->dgram_len = sizeof(struct rte_udp_hdr);

    dhcp_ccb->dhcp_info->msg_type = 0x2;
    dhcp_ccb->dhcp_info->next_server_ip = dhcp_ccb->dhcp_server_ip;
    dhcp_ccb->udp_hdr->dgram_len += sizeof(dhcp_info_t);

    unsigned char buf[128];

    dhcp_opt_t *cur = (dhcp_opt_t *)buf;
    cur->opt_type = DHCP_MSG_TYPE;
    cur->len = 0x1;
    *(cur->val) = DHCP_ACK;
    dhcp_ccb->udp_hdr->dgram_len += sizeof(dhcp_opt_t) + cur->len;

    cur = (dhcp_opt_t *)(((char *)cur) + sizeof(dhcp_opt_t) + cur->len);
    cur->opt_type = DHCP_SERVER_ID;
    cur->len = 0x4;
    rte_memcpy(cur->val, &dhcp_ccb->dhcp_server_ip, cur->len);
    dhcp_ccb->udp_hdr->dgram_len += sizeof(dhcp_opt_t) + cur->len;

    cur = (dhcp_opt_t *)(((char *)cur) + sizeof(dhcp_opt_t) + cur->len);
    cur->opt_type = DHCP_SUBNET_MASK;
    cur->len = 0x4;
    cur->val[3] = 0x00;
    cur->val[0] = cur->val[1] = cur->val[2] = 0xff;
    dhcp_ccb->udp_hdr->dgram_len += sizeof(dhcp_opt_t) + cur->len;

    cur = (dhcp_opt_t *)(((char *)cur) + sizeof(dhcp_opt_t) + cur->len);
    cur->opt_type = DHCP_LEASE_TIME;
    cur->len = 0x4;
    U32 lease_time = rte_cpu_to_be_32(LEASE_TIMEOUT); //1 hr
    rte_memcpy(cur->val, &lease_time, cur->len);
    dhcp_ccb->udp_hdr->dgram_len += sizeof(dhcp_opt_t) + cur->len;

    cur = (dhcp_opt_t *)(((char *)cur) + sizeof(dhcp_opt_t) + cur->len);
    cur->opt_type = DHCP_ROUTER;
    cur->len = 0x4;
    rte_memcpy(cur->val, &dhcp_ccb->dhcp_server_ip, cur->len);
    dhcp_ccb->udp_hdr->dgram_len += sizeof(dhcp_opt_t) + cur->len;
    
    cur = (dhcp_opt_t *)(((char *)cur) + sizeof(dhcp_opt_t) + cur->len);
    cur->opt_type = DHCP_DNS;
    cur->len = 0x8;
    U32 dns[2] = { rte_cpu_to_be_32(0x08080808), rte_cpu_to_be_32(0x01010101) };
    rte_memcpy(cur->val, &dns, cur->len);
    dhcp_ccb->udp_hdr->dgram_len += sizeof(dhcp_opt_t) + cur->len;

    cur = (dhcp_opt_t *)(((char *)cur) + sizeof(dhcp_opt_t) + cur->len);
    memset(cur, 0, 23);
    *(U8 *)cur = DHCP_END;
    dhcp_ccb->udp_hdr->dgram_len += 1 + 22;

    rte_memcpy((dhcp_ccb->dhcp_info + 1), buf, dhcp_ccb->udp_hdr->dgram_len);

    dhcp_ccb->ip_hdr->total_length += dhcp_ccb->udp_hdr->dgram_len;
    //PRINT_MESSAGE(dhcp_ccb->eth_hdr, sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t) + sizeof(struct rte_ipv4_hdr) + dhcp_ccb->ip_hdr->total_length);
    
    dhcp_ccb->udp_hdr->dgram_len = rte_cpu_to_be_16(dhcp_ccb->udp_hdr->dgram_len);
    dhcp_ccb->ip_hdr->total_length = rte_cpu_to_be_16(dhcp_ccb->ip_hdr->total_length);
    dhcp_ccb->ip_hdr->hdr_checksum = rte_ipv4_cksum(dhcp_ccb->ip_hdr);

    return TRUE;
}

STATUS build_dhcp_nak(dhcp_ccb_t *dhcp_ccb)
{
    struct rte_ether_addr macaddr;

    rte_eth_macaddr_get(0, &macaddr);
    rte_ether_addr_copy(&dhcp_ccb->eth_hdr->src_addr, &dhcp_ccb->eth_hdr->dst_addr);
    rte_ether_addr_copy(&macaddr, &dhcp_ccb->eth_hdr->src_addr);

    dhcp_ccb->ip_hdr->packet_id = ip_hdr_id++;
    dhcp_ccb->ip_hdr->packet_id = rte_cpu_to_be_16(dhcp_ccb->ip_hdr->packet_id);
    dhcp_ccb->ip_hdr->hdr_checksum = 0;
    dhcp_ccb->ip_hdr->src_addr = dhcp_ccb->dhcp_server_ip;
    dhcp_ccb->ip_hdr->dst_addr = dhcp_ccb->dhcp_info->ur_client_ip;
    dhcp_ccb->ip_hdr->total_length = sizeof(struct rte_ipv4_hdr);

    dhcp_ccb->udp_hdr->src_port = rte_cpu_to_be_16(67);
    dhcp_ccb->udp_hdr->dst_port = rte_cpu_to_be_16(68);
    dhcp_ccb->udp_hdr->dgram_cksum = 0;
    dhcp_ccb->udp_hdr->dgram_len = sizeof(struct rte_udp_hdr);

    dhcp_ccb->dhcp_info->client_ip = 0;
    dhcp_ccb->dhcp_info->ur_client_ip = 0;
    dhcp_ccb->dhcp_info->next_server_ip = 0;
    dhcp_ccb->dhcp_info->msg_type = 0x2;
    dhcp_ccb->dhcp_info->next_server_ip = dhcp_ccb->dhcp_server_ip;
    dhcp_ccb->udp_hdr->dgram_len += sizeof(dhcp_info_t);

    unsigned char buf[64];

    dhcp_opt_t *cur = (dhcp_opt_t *)buf;
    cur->opt_type = DHCP_MSG_TYPE;
    cur->len = 0x1;
    *(cur->val) = DHCP_NAK;
    dhcp_ccb->udp_hdr->dgram_len += sizeof(dhcp_opt_t) + cur->len;

    cur = (dhcp_opt_t *)(((char *)cur) + sizeof(dhcp_opt_t) + cur->len);
    cur->opt_type = DHCP_SERVER_ID;
    cur->len = 0x4;
    rte_memcpy(cur->val, &dhcp_ccb->dhcp_server_ip, cur->len);
    dhcp_ccb->udp_hdr->dgram_len += sizeof(dhcp_opt_t) + cur->len;

    cur = (dhcp_opt_t *)(((char *)cur) + sizeof(dhcp_opt_t) + cur->len);
    cur->opt_type = DHCP_CLIENT_ID;
    cur->len = RTE_ETHER_ADDR_LEN;
    rte_ether_addr_copy(&dhcp_ccb->eth_hdr->dst_addr, (struct rte_ether_addr *)(cur->val));
    dhcp_ccb->udp_hdr->dgram_len += sizeof(dhcp_opt_t) + cur->len;

    cur = (dhcp_opt_t *)(((char *)cur) + sizeof(dhcp_opt_t) + cur->len);
    memset(cur, 0, 23);
    *(U8 *)cur = DHCP_END;
    dhcp_ccb->udp_hdr->dgram_len += 1 + 22;

    rte_memcpy((dhcp_ccb->dhcp_info + 1), buf, dhcp_ccb->udp_hdr->dgram_len);

    dhcp_ccb->ip_hdr->total_length += dhcp_ccb->udp_hdr->dgram_len;
    //PRINT_MESSAGE(dhcp_ccb->eth_hdr, sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t) + sizeof(struct rte_ipv4_hdr) + dhcp_ccb->ip_hdr->total_length);
    
    dhcp_ccb->udp_hdr->dgram_len = rte_cpu_to_be_16(dhcp_ccb->udp_hdr->dgram_len);
    dhcp_ccb->ip_hdr->total_length = rte_cpu_to_be_16(dhcp_ccb->ip_hdr->total_length);
    dhcp_ccb->ip_hdr->hdr_checksum = rte_ipv4_cksum(dhcp_ccb->ip_hdr);

    return TRUE;
}