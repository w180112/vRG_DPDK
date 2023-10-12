#include <assert.h>
#include <stdlib.h>
#include <common.h>
#include "../../src/pppd/codec.h"
#include "../../src/protocol.h"

void test_build_padi() {
    U8 buffer[80];
    U16 mulen;

    PPP_INFO_t s_ppp_ccb_1 = {
        .pppoe_phase = {
            .timer_counter = 0,
            .max_retransmit = 10,
        },
        .user_num = 1,
        .vlan = 2,
    };
    U8 pkt_1[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x9c, 0x69, 0xb4, 0x61, 
    0x16, 0xdd, 0x81, 0x00, 0x00, 0x02, 0x88, 0x63, 0x11, 0x09, 0x00, 0x00, 0x00, 
    0x04, 0x01, 0x01, 0x00, 0x00};

    assert(build_padi(buffer, &mulen, &s_ppp_ccb_1) == SUCCESS);
    assert(mulen == sizeof(pkt_1));
    assert(memcmp(buffer, pkt_1, mulen) == 0);

    memset(buffer, 0, sizeof(buffer));
    s_ppp_ccb_1.pppoe_phase.timer_counter = 10;
    assert(build_padi(buffer, &mulen, &s_ppp_ccb_1) == ERROR);
}

void test_build_padr() {
    U8 buffer[80];
    U16 mulen = 0;
    struct rte_ether_hdr eth_hdr = {
        .ether_type = htons(VLAN),
    };
    vlan_header_t vlan_header = {
        .tci_union.tci_value = htons(0002),
        .next_proto = htons(ETH_P_PPP_DIS),
    };
    pppoe_header_t pppoe_header = {
        .code = 0x07,
        .ver_type = 0x11,
        .session_id = htons(0x000a),
        .length = htons(0x002c),
    };

    PPP_INFO_t s_ppp_ccb_1 = {
        .pppoe_phase = {
            .timer_counter = 0,
            .max_retransmit = 10,
            .eth_hdr = &eth_hdr,
            .vlan_header = &vlan_header,
            .pppoe_header = &pppoe_header,
        },
        .user_num = 1,
        .vlan = 2,
        .PPP_dst_mac = (struct rte_ether_addr){
            .addr_bytes = {0x74, 0x4d, 0x28, 0x8d, 0x00, 0x31},
        },
    };
    U8 pppoe_header_tag[44] = {0x01, 0x03, 0x00, 0x04, 0xdb, 0xce, 0x00, 0x00,
    0x01, 0x01, 0x00, 0x00, 0x01, 0x02, 0x00, 0x08, 0x4d, 0x69, 0x6b, 0x72, 
    0x6f, 0x54, 0x69, 0x6b, 0x01, 0x01, 0x00, 0x10, 0x76, 0x72, 0x67, 0x5f, 
    0x73, 0x65, 0x72, 0x76, 0x65, 0x72};
    s_ppp_ccb_1.pppoe_phase.pppoe_header_tag = (pppoe_header_tag_t *)pppoe_header_tag;
    char pkt_1[] = {0x74, 0x4d, 0x28, 0x8d, 0x00, 0x31, 0x9c, 0x69, 0xb4, 0x61, 
    0x16, 0xdd, 0x81, 0x00, 0x00, 0x02, 0x88, 0x63, 0x11, 0x19, 0x00, 0x0a, 0x00, 
    0x0c, 0x01, 0x01, 0x00, 0x00, 0x01, 0x03, 0x00, 0x04, 0xdb, 0xce, 0x00, 0x00};

    assert(build_padr(buffer, &mulen, &s_ppp_ccb_1) == SUCCESS);
    assert(mulen == sizeof(pkt_1));
    assert(memcmp(buffer, pkt_1, mulen) == 0);

    memset(buffer, 0, sizeof(buffer));
    s_ppp_ccb_1.pppoe_phase.timer_counter = 10;
    assert(build_padr(buffer, &mulen, &s_ppp_ccb_1) == ERROR);
}