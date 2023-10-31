#include <stdlib.h>
#include <assert.h>
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
        .code = PADO,
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

void test_build_padt() {
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
        .code = PADS,
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
        .session_id = htons(0x000a),
    };
    char pkt_1[] = {0x74, 0x4d, 0x28, 0x8d, 0x00, 0x31, 0x9c, 0x69, 0xb4, 0x61, 
    0x16, 0xdd, 0x81, 0x00, 0x00, 0x02, 0x88, 0x63, 0x11, 0xa7, 0x00, 0x0a, 0x00, 
    0x00};
    
    build_padt(buffer, &mulen, &s_ppp_ccb_1);
    assert(mulen == sizeof(pkt_1));
    assert(memcmp(buffer, pkt_1, mulen) == 0);
}

void test_build_config_request() {
    U8 buffer[80];
    U16 mulen = 0;

    PPP_INFO_t s_ppp_ccb_1 = {
        .ppp_phase = {{
            .timer_counter = 0,
            .max_retransmit = 10,
        },{
            .timer_counter = 0,
            .max_retransmit = 10,
        },},
        .user_num = 1,
        .vlan = 2,
        .PPP_dst_mac = (struct rte_ether_addr){
            .addr_bytes = {0x74, 0x4d, 0x28, 0x8d, 0x00, 0x31},
        },
        .session_id = htons(0x000a),
        .cp = 0,
    };

    char pkt_lcp[] = {0x74, 0x4d, 0x28, 0x8d, 0x00, 0x31, 0x9c, 0x69, 0xb4, 0x61, 
    0x16, 0xdd, 0x81, 0x00, 0x00, 0x02, 0x88, 0x64, 0x11, 0x00, 0x00, 0x0a, 0x00, 
    0x10, 0xc0, 0x21, 0x01, 0x01, 0x00, 0x0e, 0x01, 0x04, 0x05, 0xd0, 0x05, 0x06, 
    0x00, 0x01, 0x02, 0x03};
    char pkt_ipcp[] = {0x74, 0x4d, 0x28, 0x8d, 0x00, 0x31, 0x9c, 0x69, 0xb4, 0x61, 
    0x16, 0xdd, 0x81, 0x00, 0x00, 0x02, 0x88, 0x64, 0x11, 0x00, 0x00, 0x0a, 0x00, 
    0x0c, 0x80, 0x21, 0x01, 0x01, 0x00, 0x0a, 0x03, 0x06, 0x00, 0x00, 0x00, 0x00};

    /* test LCP */
    build_config_request(buffer, &mulen, &s_ppp_ccb_1);
    assert(mulen == sizeof(pkt_lcp));
    assert(memcmp(buffer, pkt_lcp, 26/* only memcmp to lcp field */) == 0);
    ppp_header_t *test_ppp_hdr = (ppp_header_t *)(buffer + 26);
    assert(test_ppp_hdr->code == CONFIG_REQUEST);
    assert(test_ppp_hdr->length == htons(0x000e));
    ppp_options_t *test_ppp_options = (ppp_options_t *)(test_ppp_hdr + 1);
    assert(test_ppp_options->type == MRU);
    assert(test_ppp_options->length == 0x04);
    test_ppp_options = (ppp_options_t *)((U8 *)test_ppp_options + test_ppp_options->length);
    assert(test_ppp_options->type == MAGIC_NUM);
    assert(test_ppp_options->length == 0x06);

    /* test IPCP */
    memset(buffer, 0, sizeof(buffer));
    s_ppp_ccb_1.cp = 1;
    build_config_request(buffer, &mulen, &s_ppp_ccb_1);
    assert(mulen == sizeof(pkt_ipcp));
    assert(memcmp(buffer, pkt_ipcp, 26/* only memcmp to ipcp field */) == 0);
    test_ppp_hdr = (ppp_header_t *)(buffer + 26);
    assert(test_ppp_hdr->code == CONFIG_REQUEST);
    assert(test_ppp_hdr->length == htons(0x000a));
    test_ppp_options = (ppp_options_t *)(test_ppp_hdr + 1);
    assert(test_ppp_options->type == IP_ADDRESS);
    assert(test_ppp_options->length == 0x06);
}


void test_build_config_ack() {
    U8 buffer[80];
    U16 mulen = 0;

    PPP_INFO_t s_ppp_ccb_1 = {
        .ppp_phase = {{
            .timer_counter = 0,
            .max_retransmit = 10,
            .eth_hdr = &(struct rte_ether_hdr) {
                .ether_type = htons(VLAN),
            },
            .vlan_header = &(vlan_header_t) {
                .tci_union.tci_value = htons(0002),
                .next_proto = htons(ETH_P_PPP_SES),
            },
            .pppoe_header = &(pppoe_header_t) {
                .code = 0,
                .ver_type = 0x11,
                .session_id = htons(0x000a),
                .length = htons(0x0014),
            },
            .ppp_payload = &(ppp_payload_t) {
                .ppp_protocol = htons(LCP_PROTOCOL),
            },
            .ppp_hdr = &(ppp_header_t) {
                .code = CONFIG_REQUEST,
                .identifier = 0x01,
                .length = htons(0x0012),
            },
            .ppp_options = (ppp_options_t *)(U8 []){
                0x03, 0x04, 0xc0, 0x23, 0x01, 0x04, 0x05, 0xd0, 0x05, 0x06, 0x01, 0x02, 0x03, 0x04
            }, // MRU, AUTH, MAGIC NUMBER
        },{
            .timer_counter = 0,
            .max_retransmit = 10,
            .eth_hdr = &(struct rte_ether_hdr) {
                .ether_type = htons(VLAN),
            },
            .vlan_header = &(vlan_header_t) {
                .tci_union.tci_value = htons(0002),
                .next_proto = htons(ETH_P_PPP_SES),
            },
            .pppoe_header = &(pppoe_header_t) {
                .code = 0,
                .ver_type = 0x11,
                .session_id = htons(0x000a),
                .length = htons(0x000c),
            },
            .ppp_payload = &(ppp_payload_t) {
                .ppp_protocol = htons(IPCP_PROTOCOL),
            },
            .ppp_hdr = &(ppp_header_t) {
                .code = CONFIG_REQUEST,
                .identifier = 0x01,
                .length = htons(0x000a),
            },
            .ppp_options = (ppp_options_t *)(U8 []){
                0x03, 0x06, 0xc0, 0xa8, 0xc8, 0x01
            }, // IP_ADDRESS
        },},
        .user_num = 1,
        .vlan = 2,
        .PPP_dst_mac = (struct rte_ether_addr){
            .addr_bytes = {0x74, 0x4d, 0x28, 0x8d, 0x00, 0x31},
        },
        .session_id = htons(0x000a),
        .cp = 0,
    };

    char pkt_lcp[] = {/* mac */0x74, 0x4d, 0x28, 0x8d, 0x00, 0x31, 0x9c, 0x69, 0xb4, 
    0x61, 0x16, 0xdd, 0x81, 0x00, /* vlan */0x00, 0x02, 0x88, 0x64, /* pppoe hdr */
    0x11, 0x00, 0x00, 0x0a, 0x00, 0x14, /* ppp protocol */0xc0, 0x21, /* ppp hdr*/
    0x02, 0x01, 0x00, 0x12, /* ppp option */0x03, 0x04, 0xc0, 0x23, 0x01, 0x04, 0x05, 
    0xd0, 0x05, 0x06, 0x01, 0x02, 0x03, 0x04};
    char pkt_ipcp[] = {/* mac */0x74, 0x4d, 0x28, 0x8d, 0x00, 0x31, 0x9c, 0x69, 0xb4, 
    0x61, 0x16, 0xdd, 0x81, 0x00, /* vlan */0x00, 0x02, 0x88, 0x64, /* pppoe hdr */
    0x11, 0x00, 0x00, 0x0a, 0x00, 0x0c, /* ppp protocol */0x80, 0x21, /* ppp hdr*/
    0x02, 0x01, 0x00, 0x0a, /* ppp option */0x03, 0x06, 0xc0, 0xa8, 0xc8, 0x01};

    /* test LCP */
    build_config_ack(buffer, &mulen, &s_ppp_ccb_1);
    assert(mulen == sizeof(pkt_lcp));
    assert(memcmp(buffer, pkt_lcp, sizeof(pkt_lcp)) == 0);

    memset(buffer, 0, sizeof(buffer));
    /* test IPCP */
    s_ppp_ccb_1.cp = 1;
    build_config_ack(buffer, &mulen, &s_ppp_ccb_1);
    assert(mulen == sizeof(pkt_ipcp));
    assert(memcmp(buffer, pkt_ipcp, sizeof(pkt_ipcp)) == 0);
}

void test_build_terminate_request() {
    U8 buffer[80];
    U16 mulen = 0;

    PPP_INFO_t s_ppp_ccb_1 = {
        .ppp_phase = {{
            .timer_counter = 0,
            .max_retransmit = 10,
        },{
            .timer_counter = 0,
            .max_retransmit = 10,
        },},
        .user_num = 1,
        .vlan = 2,
        .PPP_dst_mac = (struct rte_ether_addr){
            .addr_bytes = {0x74, 0x4d, 0x28, 0x8d, 0x00, 0x31},
        },
        .session_id = htons(0x000a),
        .cp = 0,
    };

    char pkt_lcp[] = {/* mac */0x74, 0x4d, 0x28, 0x8d, 0x00, 0x31, 0x9c, 0x69, 0xb4, 
    0x61, 0x16, 0xdd, 0x81, 0x00, /* vlan */0x00, 0x02, 0x88, 0x64, /* pppoe hdr */
    0x11, 0x00, 0x00, 0x0a, 0x00, 0x06, /* ppp protocol */0xc0, 0x21, /* ppp hdr*/
    0x05, 0x03, 0x00, 0x04};
    char pkt_ipcp[] = {/* mac */0x74, 0x4d, 0x28, 0x8d, 0x00, 0x31, 0x9c, 0x69, 0xb4, 
    0x61, 0x16, 0xdd, 0x81, 0x00, /* vlan */0x00, 0x02, 0x88, 0x64, /* pppoe hdr */
    0x11, 0x00, 0x00, 0x0a, 0x00, 0x06, /* ppp protocol */0x80, 0x21, /* ppp hdr*/
    0x05, 0x03, 0x00, 0x04};

    /* test LCP */
    build_terminate_request(buffer, &mulen, &s_ppp_ccb_1);
    assert(mulen == sizeof(pkt_lcp));
    assert(memcmp(buffer, pkt_lcp, sizeof(pkt_lcp)) == 0);

    /* test IPCP */
    memset(buffer, 0, sizeof(buffer));
    s_ppp_ccb_1.cp = 1;
    build_terminate_request(buffer, &mulen, &s_ppp_ccb_1);
    assert(mulen == sizeof(pkt_ipcp));
    assert(memcmp(buffer, pkt_ipcp, sizeof(pkt_ipcp)) == 0);
}
