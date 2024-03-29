#include <common.h>
#include <rte_mbuf.h>
#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <sys/mman.h>
#include "../vrg.h"
#include "dhcp_fsm.h"

extern STATUS dhcp_fsm(dhcp_ccb_t *dhcp_ccb, U16 event);
void release_lan_user(dhcp_ccb_t *dhcp_ccb);

struct rte_ether_addr zero_mac;
static VRG_t *vrg_ccb;

STATUS dhcp_init(void *ccb)
{
    vrg_ccb = (VRG_t *)ccb;
    vrg_ccb->dhcp_ccb = mmap(NULL, sizeof(dhcp_ccb_t)*vrg_ccb->user_count, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
	if (vrg_ccb->dhcp_ccb == MAP_FAILED) { 
		perror("map mem");
		vrg_ccb->dhcp_ccb = NULL;
		return ERROR;
	}
    dhcp_fsm_init(vrg_ccb);
    dhcp_ccb_t *dhcp_ccb = vrg_ccb->dhcp_ccb;

    for(int i=0; i<RTE_ETHER_ADDR_LEN; i++)
        zero_mac.addr_bytes[i] = 0;

    for(int i=0; i<vrg_ccb->user_count; i++) {
        for(int j=0; j<LAN_USER; j++) {
            rte_timer_init(&(dhcp_ccb[i].lan_user_info[j].timer));
            rte_timer_init(&(dhcp_ccb[i].lan_user_info[j].lan_user_timer));
	        dhcp_ccb[i].dhcp_server_ip = rte_cpu_to_be_32(0xc0a80201);
            dhcp_ccb[i].lan_user_info[j].lan_user_used = FALSE;
            rte_ether_addr_copy(&zero_mac, &dhcp_ccb[i].lan_user_info[j].mac_addr);
		    dhcp_ccb[i].ip_pool[j].used = FALSE;
		    dhcp_ccb[i].ip_pool[j].ip_addr = rte_cpu_to_be_32(0xc0a80200 | (j + 101));
            rte_ether_addr_copy(&zero_mac, &dhcp_ccb[i].ip_pool[j].mac_addr);
            dhcp_ccb[i].lan_user_info[j].state = S_DHCP_INIT;
            rte_atomic16_init(&dhcp_ccb[i].dhcp_bool);
        }
    }

    return SUCCESS;
}

int dhcpd(struct rte_mbuf *single_pkt, struct rte_ether_hdr *eth_hdr, vlan_header_t *vlan_header, struct rte_ipv4_hdr *ip_hdr, struct rte_udp_hdr *udp_hdr, U16 user_index)
{
    BIT16 event;
    dhcp_ccb_t *dhcp_ccb = vrg_ccb->dhcp_ccb;
    int lan_user_index = -1;

    if (user_index >= vrg_ccb->user_count) {
        rte_pktmbuf_free(single_pkt);
        return -1;
    }

    /* Pick one index from lan_user_info array and save it to dhcp_ccb */
    for(int i=0; i<LAN_USER; i++) {
        if (dhcp_ccb[user_index].lan_user_info[i].lan_user_used == FALSE) {
            lan_user_index = dhcp_ccb[user_index].cur_lan_user_index = i;
            rte_ether_addr_copy(&eth_hdr->src_addr, &dhcp_ccb[user_index].lan_user_info[i].mac_addr);
            dhcp_ccb[user_index].lan_user_info[i].lan_user_used = TRUE;
            break;
        }
        else if (rte_is_same_ether_addr(&eth_hdr->src_addr, &dhcp_ccb[user_index].lan_user_info[i].mac_addr)) {
            lan_user_index = dhcp_ccb[user_index].cur_lan_user_index = i;
            break;
        }
    }
    /* If dhcp ip pool is full, drop the packet */
    if (lan_user_index < 0) {
        rte_pktmbuf_free(single_pkt);
        return -1;
    }
    /* If no more packet from the host, clear all information in dhcp_ccb */
    rte_timer_stop(&dhcp_ccb[user_index].lan_user_info[lan_user_index].timer);
	rte_timer_reset(&dhcp_ccb[user_index].lan_user_info[lan_user_index].timer, LEASE_TIMEOUT * 2 * rte_get_timer_hz(), SINGLE, vrg_ccb->lcore.timer_thread, (rte_timer_cb_t)release_lan_user, &dhcp_ccb[user_index]);

    event = dhcp_decode(&dhcp_ccb[user_index], eth_hdr, vlan_header, ip_hdr, udp_hdr);
    if (event < 0) {
        release_lan_user(&dhcp_ccb[user_index]);
        rte_pktmbuf_free(single_pkt);
        return -1;
    }
    else if (event == 0)
        return 0;
    if (dhcp_fsm(&dhcp_ccb[user_index], event) == FALSE) {
        release_lan_user(&dhcp_ccb[user_index]);
        rte_pktmbuf_free(single_pkt);
        return -1;
    }
    single_pkt->data_len = single_pkt->pkt_len = sizeof(struct rte_ether_hdr) + sizeof(vlan_header_t) + sizeof(struct rte_ipv4_hdr) + rte_be_to_cpu_16(dhcp_ccb[user_index].ip_hdr->total_length);
    return 1;
}

void release_lan_user(dhcp_ccb_t *dhcp_ccb)
{
    U8 lan_user_index = dhcp_ccb->cur_lan_user_index;

    dhcp_ccb->ip_pool[dhcp_ccb->cur_ip_pool_index].used = FALSE;
    dhcp_ccb->lan_user_info[lan_user_index].lan_user_used = FALSE;
    rte_ether_addr_copy(&zero_mac, &dhcp_ccb->lan_user_info[lan_user_index].mac_addr);
}