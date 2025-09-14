#include <stdlib.h>
#include <assert.h>
#include <common.h>
#include "../../src/pppd/codec.h"
#include "../../src/protocol.h"

void test_build_padi() {
    U8 buffer[80] = { 0 };
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

    // TODO: move timeout test to send_pkt()
    /*memset(buffer, 0, sizeof(buffer));
    s_ppp_ccb_1.pppoe_phase.timer_counter = 10;
    assert(build_padi(buffer, &mulen, &s_ppp_ccb_1) == ERROR);*/
}

void test_build_padr() {
    U8 buffer[80] = { 0 };
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
        },
        .user_num = 1,
        .vlan = 2,
        .PPP_dst_mac = (struct rte_ether_addr){
            .addr_bytes = {0x74, 0x4d, 0x28, 0x8d, 0x00, 0x31},
        },
        .eth_hdr = eth_hdr,
        .vlan_header = vlan_header,
        .pppoe_header = pppoe_header,
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

    // TODO: move timeout test to send_pkt()
    /*memset(buffer, 0, sizeof(buffer));
    s_ppp_ccb_1.pppoe_phase.timer_counter = 10;
    assert(build_padr(buffer, &mulen, &s_ppp_ccb_1) == ERROR);*/
}

void test_build_padt() {
    U8 buffer[80] = { 0 };
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
        },
        .user_num = 1,
        .vlan = 2,
        .PPP_dst_mac = (struct rte_ether_addr){
            .addr_bytes = {0x74, 0x4d, 0x28, 0x8d, 0x00, 0x31},
        },
        .session_id = htons(0x000a),
        .eth_hdr = eth_hdr,
        .vlan_header = vlan_header,
        .pppoe_header = pppoe_header,
    };
    char pkt_1[] = {0x74, 0x4d, 0x28, 0x8d, 0x00, 0x31, 0x9c, 0x69, 0xb4, 0x61, 
    0x16, 0xdd, 0x81, 0x00, 0x00, 0x02, 0x88, 0x63, 0x11, 0xa7, 0x00, 0x0a, 0x00, 
    0x00};
    
    build_padt(buffer, &mulen, &s_ppp_ccb_1);
    assert(mulen == sizeof(pkt_1));
    assert(memcmp(buffer, pkt_1, mulen) == 0);
}

void test_build_config_request() {
    U8 buffer[80] = { 0 };
    U16 mulen = 0;

    PPP_INFO_t s_ppp_ccb[] = {
        {
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
            .magic_num = htonl(0x01020304),
            .identifier = 0xfd,
            .hsi_ipv4 = 0x0,
        },
    };

    U8 pkt_lcp[] = {/* mac */0x74, 0x4d, 0x28, 0x8d, 0x00, 0x31, 0x9c, 0x69, 0xb4, 
    0x61, 0x16, 0xdd, 0x81, 0x00, /* vlan */0x00, 0x02, 0x88, 0x64, /* pppoe hdr */
    0x11, 0x00, 0x00, 0x0a, 0x00, 0x10, /* ppp protocol */0xc0, 0x21, /* ppp hdr */
    0x01, 0xfe, 0x00, 0x0e, /* ppp option */0x01, 0x04, 0x05, 0xd0, 0x05, 0x06, 0x01, 
    0x02, 0x03, 0x04};
    U8 pkt_ipcp_1[] = {/* mac */0x74, 0x4d, 0x28, 0x8d, 0x00, 0x31, 0x9c, 0x69, 0xb4, 
    0x61, 0x16, 0xdd, 0x81, 0x00, /* vlan */0x00, 0x02, 0x88, 0x64, /* pppoe hdr */
    0x11, 0x00, 0x00, 0x0a, 0x00, 0x0c, /* ppp protocol */0x80, 0x21, /* ppp hdr */
    0x01, 0xff, 0x00, 0x0a, /* ppp option */0x03, 0x06, 0x00, 0x00, 0x00, 0x00};
    U8 pkt_ipcp_2[] = {/* mac */0x74, 0x4d, 0x28, 0x8d, 0x00, 0x31, 0x9c, 0x69, 0xb4, 
    0x61, 0x16, 0xdd, 0x81, 0x00, /* vlan */0x00, 0x02, 0x88, 0x64, /* pppoe hdr */
    0x11, 0x00, 0x00, 0x0a, 0x00, 0x0c, /* ppp protocol */0x80, 0x21, /* ppp hdr */
    0x01, 0x01, 0x00, 0x0a, /* ppp option */0x03, 0x06, 0xc0, 0xa8, 0xc8, 0x01};

    for(int i=0; i<sizeof(s_ppp_ccb)/sizeof(s_ppp_ccb[0]); i++) {
        /* test LCP */
        build_config_request(buffer, &mulen, &s_ppp_ccb[0]);
        assert(mulen == sizeof(pkt_lcp));
        assert(memcmp(buffer, pkt_lcp, sizeof(pkt_lcp)) == 0);
        /* test IPCP */
        s_ppp_ccb[0].cp = 1;
        memset(buffer, 0, sizeof(buffer));
        build_config_request(buffer, &mulen, &s_ppp_ccb[0]);
        assert(mulen == sizeof(pkt_ipcp_1));
        assert(memcmp(buffer, pkt_ipcp_1, sizeof(pkt_ipcp_1)) == 0);
        s_ppp_ccb[0].hsi_ipv4 = htonl(0xc0a8c801);
        memset(buffer, 0, sizeof(buffer));
        build_config_request(buffer, &mulen, &s_ppp_ccb[0]);
        assert(mulen == sizeof(pkt_ipcp_2));
        assert(memcmp(buffer, pkt_ipcp_2, sizeof(pkt_ipcp_2)) == 0);
    }
}

void test_build_config_ack() {
    U8 buffer[80] = { 0 };
    U16 mulen = 0;

    PPP_INFO_t s_ppp_ccb_1 = {
        .ppp_phase = {{
            .timer_counter = 0,
            .max_retransmit = 10,
            .ppp_payload = (ppp_payload_t) {
                .ppp_protocol = htons(LCP_PROTOCOL),
            },
            .ppp_hdr = (ppp_header_t) {
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
            .ppp_payload = (ppp_payload_t) {
                .ppp_protocol = htons(IPCP_PROTOCOL),
            },
            .ppp_hdr = (ppp_header_t) {
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
        .eth_hdr = (struct rte_ether_hdr) {
            .ether_type = htons(VLAN),
        },
        .vlan_header = (vlan_header_t) {
            .tci_union.tci_value = htons(0002),
            .next_proto = htons(ETH_P_PPP_SES),
        },
        .pppoe_header = (pppoe_header_t) {
            .code = 0,
            .ver_type = 0x11,
            .session_id = htons(0x000a),
            .length = htons(0x0014),
        },
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
    s_ppp_ccb_1.pppoe_header.length = htons(0x000c);
    build_config_ack(buffer, &mulen, &s_ppp_ccb_1);
    assert(mulen == sizeof(pkt_ipcp));
    assert(memcmp(buffer, pkt_ipcp, sizeof(pkt_ipcp)) == 0);
}

void test_build_terminate_request() {
    U8 buffer[80] = { 0 };
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
    assert(memcmp(buffer, pkt_lcp, 26/* only memcmp to ipcp field */) == 0);
    ppp_header_t *test_ppp_hdr = (ppp_header_t *)(buffer + 26);
    assert(test_ppp_hdr->code == TERMIN_REQUEST);
    assert(test_ppp_hdr->length == htons(0x0004));

    /* test IPCP */
    memset(buffer, 0, sizeof(buffer));
    s_ppp_ccb_1.cp = 1;
    build_terminate_request(buffer, &mulen, &s_ppp_ccb_1);
    assert(mulen == sizeof(pkt_ipcp));
    assert(memcmp(buffer, pkt_ipcp, 26/* only memcmp to ipcp field */) == 0);
    test_ppp_hdr = (ppp_header_t *)(buffer + 26);
    assert(test_ppp_hdr->code == TERMIN_REQUEST);
    assert(test_ppp_hdr->length == htons(0x0004));
}

void test_build_config_nak_rej()
{
    U8 buffer[80] = {0};
    U16 mulen = 0;

    PPP_INFO_t s_ppp_ccb_1 = {
        .ppp_phase = {{
            .timer_counter = 0,
            .max_retransmit = 10,
            .ppp_payload = (ppp_payload_t) {
                .ppp_protocol = htons(LCP_PROTOCOL),
            },
            .ppp_hdr = (ppp_header_t) {
                .code = CONFIG_REJECT,
                .identifier = 0x01,
                .length = htons(0x0008),
            },
            .ppp_options = (ppp_options_t *)(U8 []){
                0x03, 0x04, 0xc0, 0x23
            }, // CHAP
        },{
            .timer_counter = 0,
            .max_retransmit = 10,
            .ppp_payload = (ppp_payload_t) {
                .ppp_protocol = htons(IPCP_PROTOCOL),
            },
            .ppp_hdr = (ppp_header_t) {
                .code = CONFIG_REJECT,
                .identifier = 0x01,
                .length = htons(0x000a),
            },
            .ppp_options = (ppp_options_t *)(U8 []){
                0x83, 0x06, 0x00, 0x00, 0x00, 0x00
            }, // Secondary DNS
        },},
        .user_num = 1,
        .vlan = 2,
        .PPP_dst_mac = (struct rte_ether_addr){
            .addr_bytes = {0x74, 0x4d, 0x28, 0x8d, 0x00, 0x31},
        },
        .session_id = htons(0x000a),
        .cp = 0,
        .eth_hdr = (struct rte_ether_hdr) {
            .ether_type = htons(VLAN),
        },
        .vlan_header = (vlan_header_t) {
            .tci_union.tci_value = htons(0002),
            .next_proto = htons(ETH_P_PPP_SES),
        },
        .pppoe_header = (pppoe_header_t) {
            .code = 0,
            .ver_type = 0x11,
            .session_id = htons(0x000a),
            .length = htons(0x000a),
        },
    };
    PPP_INFO_t s_ppp_ccb_2 = {
        .ppp_phase = {{
            .timer_counter = 0,
            .max_retransmit = 10,
            .ppp_payload = (ppp_payload_t) {
                .ppp_protocol = htons(LCP_PROTOCOL),
            },
            .ppp_hdr = (ppp_header_t) {
                .code = CONFIG_NAK,
                .identifier = 0x01,
                .length = htons(0x0008),
            },
            .ppp_options = (ppp_options_t *)(U8 []){
                0x01, 0x04, 0x05, 0xd0
            }, // MRU
        },{
            .timer_counter = 0,
            .max_retransmit = 10,
            .ppp_payload = (ppp_payload_t) {
                .ppp_protocol = htons(IPCP_PROTOCOL),
            },
            .ppp_hdr = (ppp_header_t) {
                .code = CONFIG_NAK,
                .identifier = 0x01,
                .length = htons(0x0010),
            },
            .ppp_options = (ppp_options_t *)(U8 []){
                0xc0, 0xa8, 0xc8, 0xfe, 0x81, 0x06, 0xc0, 0xa8, 0x0a, 0x01
            }, // IP and Primary DNS
        },},
        .user_num = 1,
        .vlan = 2,
        .PPP_dst_mac = (struct rte_ether_addr){
            .addr_bytes = {0x74, 0x4d, 0x28, 0x8d, 0x00, 0x31},
        },
        .session_id = htons(0x000a),
        .cp = 0,
        .eth_hdr = (struct rte_ether_hdr) {
            .ether_type = htons(VLAN),
        },
        .vlan_header = (vlan_header_t) {
            .tci_union.tci_value = htons(0002),
            .next_proto = htons(ETH_P_PPP_SES),
        },
        .pppoe_header = (pppoe_header_t) {
            .code = 0,
            .ver_type = 0x11,
            .session_id = htons(0x000a),
            .length = htons(0x000a),
        },
    };

    char pkt_lcp_1[] = {/* mac */0x74, 0x4d, 0x28, 0x8d, 0x00, 0x31, 0x9c, 0x69, 0xb4, 
    0x61, 0x16, 0xdd, 0x81, 0x00, /* vlan */0x00, 0x02, 0x88, 0x64, /* pppoe hdr */
    0x11, 0x00, 0x00, 0x0a, 0x00, 0x0a, /* ppp protocol */0xc0, 0x21, /* ppp hdr*/
    0x04, 0x01, 0x00, 0x08, /* ppp option */0x03, 0x04, 0xc0, 0x23};
    char pkt_ipcp_1[] = {/* mac */0x74, 0x4d, 0x28, 0x8d, 0x00, 0x31, 0x9c, 0x69, 0xb4, 
    0x61, 0x16, 0xdd, 0x81, 0x00, /* vlan */0x00, 0x02, 0x88, 0x64, /* pppoe hdr */
    0x11, 0x00, 0x00, 0x0a, 0x00, 0x0c, /* ppp protocol */0x80, 0x21, /* ppp hdr*/
    0x04, 0x01, 0x00, 0x0a, /* ppp option */0x83, 0x06, 0x00, 0x00, 0x00, 0x00};
    char pkt_lcp_2[] = {/* mac */0x74, 0x4d, 0x28, 0x8d, 0x00, 0x31, 0x9c, 0x69, 0xb4, 
    0x61, 0x16, 0xdd, 0x81, 0x00, /* vlan */0x00, 0x02, 0x88, 0x64, /* pppoe hdr */
    0x11, 0x00, 0x00, 0x0a, 0x00, 0x0a, /* ppp protocol */0xc0, 0x21, /* ppp hdr*/
    0x03, 0x01, 0x00, 0x08, /* ppp option */0x01, 0x04, 0x05, 0xd0};
    char pkt_ipcp_2[] = {/* mac */0x74, 0x4d, 0x28, 0x8d, 0x00, 0x31, 0x9c, 0x69, 0xb4, 
    0x61, 0x16, 0xdd, 0x81, 0x00, /* vlan */0x00, 0x02, 0x88, 0x64, /* pppoe hdr */
    0x11, 0x00, 0x00, 0x0a, 0x00, 0x10, /* ppp protocol */0x80, 0x21, /* ppp hdr*/
    0x03, 0x01, 0x00, 0x10, /* ppp option */0xc0, 0xa8, 0xc8, 0xfe, 0x81, 0x06, 0xc0, 
    0xa8, 0x0a, 0x01};

    /* test LCP */
    build_config_nak_rej(buffer, &mulen, &s_ppp_ccb_1);
    assert(mulen == sizeof(pkt_lcp_1));
    assert(memcmp(buffer, pkt_lcp_1, sizeof(pkt_lcp_1)) == 0);

    /* test IPCP */
    s_ppp_ccb_1.cp = 1;
    s_ppp_ccb_1.pppoe_header.length = htons(0x000c);
    memset(buffer, 0, sizeof(buffer));
    build_config_nak_rej(buffer, &mulen, &s_ppp_ccb_1);
    assert(mulen == sizeof(pkt_ipcp_1));
    assert(memcmp(buffer, pkt_ipcp_1, sizeof(pkt_ipcp_1)) == 0);

    s_ppp_ccb_2.cp = 0;
    memset(buffer, 0, sizeof(buffer));
    build_config_nak_rej(buffer, &mulen, &s_ppp_ccb_2);
    assert(mulen == sizeof(pkt_lcp_2));
    assert(memcmp(buffer, pkt_lcp_2, sizeof(pkt_lcp_2)) == 0);    

    s_ppp_ccb_2.cp = 1;
    s_ppp_ccb_2.pppoe_header.length = htons(0x0010);
    memset(buffer, 0, sizeof(buffer));
    build_config_nak_rej(buffer, &mulen, &s_ppp_ccb_2);
    assert(mulen == sizeof(pkt_ipcp_2));
    assert(memcmp(buffer, pkt_ipcp_2, sizeof(pkt_ipcp_2)) == 0);
}

void test_build_terminate_ack() 
{
    U8 buffer[80] = { 0 };
    U16 mulen = 0;

    PPP_INFO_t s_ppp_ccb_1 = {
        .ppp_phase = {{
            .timer_counter = 0,
            .max_retransmit = 10,
            .ppp_payload = (ppp_payload_t) {
                .ppp_protocol = htons(LCP_PROTOCOL),
            },
            .ppp_hdr = (ppp_header_t) {
                .code = TERMIN_REQUEST,
                .identifier = 0x01,
                .length = htons(0x0012),
            },
            /* this field is not used, we juts leave this here to make sure it won't
            be inserted into terminate ack packet */
            .ppp_options = (ppp_options_t *)(U8 []){
                0x03, 0x04, 0xc0, 0x23, 0x01, 0x04, 0x05, 0xd0, 0x05, 0x06, 0x01, 0x02, 0x03, 0x04
            }, // MRU, AUTH, MAGIC NUMBER
        },{
            .timer_counter = 0,
            .max_retransmit = 10,
            .ppp_payload = (ppp_payload_t) {
                .ppp_protocol = htons(IPCP_PROTOCOL),
            },
            .ppp_hdr = (ppp_header_t) {
                .code = CONFIG_REQUEST,
                .identifier = 0x01,
                .length = htons(0x000a),
            },
            /* this field is not used, we juts leave this here to make sure it won't
            be inserted into terminate ack packet */
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
        .eth_hdr = (struct rte_ether_hdr) {
            .ether_type = htons(VLAN),
        },
        .vlan_header = (vlan_header_t) {
            .tci_union.tci_value = htons(0002),
            .next_proto = htons(ETH_P_PPP_SES),
        },
        .pppoe_header = (pppoe_header_t) {
            .code = 0,
            .ver_type = 0x11,
            .session_id = htons(0x000a),
            .length = htons(0x0014),
        },
    };

    char pkt_lcp[] = {/* mac */0x74, 0x4d, 0x28, 0x8d, 0x00, 0x31, 0x9c, 0x69, 0xb4, 
    0x61, 0x16, 0xdd, 0x81, 0x00, /* vlan */0x00, 0x02, 0x88, 0x64, /* pppoe hdr */
    0x11, 0x00, 0x00, 0x0a, 0x00, 0x06, /* ppp protocol */0xc0, 0x21, /* ppp hdr*/
    0x06, 0x01, 0x00, 0x04};
    char pkt_ipcp[] = {/* mac */0x74, 0x4d, 0x28, 0x8d, 0x00, 0x31, 0x9c, 0x69, 0xb4, 
    0x61, 0x16, 0xdd, 0x81, 0x00, /* vlan */0x00, 0x02, 0x88, 0x64, /* pppoe hdr */
    0x11, 0x00, 0x00, 0x0a, 0x00, 0x06, /* ppp protocol */0x80, 0x21, /* ppp hdr*/
    0x06, 0x01, 0x00, 0x04};

    /* test LCP */
    build_terminate_ack(buffer, &mulen, &s_ppp_ccb_1);
    assert(mulen == sizeof(pkt_lcp));
    assert(memcmp(buffer, pkt_lcp, sizeof(pkt_lcp)) == 0);

    memset(buffer, 0, sizeof(buffer));
    /* test IPCP */
    s_ppp_ccb_1.cp = 1;
    build_terminate_ack(buffer, &mulen, &s_ppp_ccb_1);
    assert(mulen == sizeof(pkt_ipcp));
    assert(memcmp(buffer, pkt_ipcp, sizeof(pkt_ipcp)) == 0);
}

void test_build_echo_reply() 
{
    U8 buffer[80] = { 0 };
    U16 mulen = 0;

    PPP_INFO_t s_ppp_ccb_1 = {
        .ppp_phase = {{
            .timer_counter = 0,
            .max_retransmit = 10,
            .ppp_payload = (ppp_payload_t) {
                .ppp_protocol = htons(LCP_PROTOCOL),
            },
            .ppp_hdr = (ppp_header_t) {
                .code = CONFIG_REQUEST,
                .identifier = 0x01,
                .length = htons(0x0008),
            },
            .ppp_options = (ppp_options_t *)(U8 []){
                0x05, 0x06, 0x07, 0x08
            }, // echo requester's magic number
        },{},},
        .user_num = 1,
        .vlan = 2,
        .PPP_dst_mac = (struct rte_ether_addr){
            .addr_bytes = {0x74, 0x4d, 0x28, 0x8d, 0x00, 0x31},
        },
        .session_id = htons(0x000a),
        .cp = 0,
        .magic_num = htonl(0x01020304),
        .eth_hdr = (struct rte_ether_hdr) {
            .ether_type = htons(VLAN),
        },
        .vlan_header = (vlan_header_t) {
            .tci_union.tci_value = htons(0002),
            .next_proto = htons(ETH_P_PPP_SES),
        },
        .pppoe_header = (pppoe_header_t) {
            .code = 0,
            .ver_type = 0x11,
            .session_id = htons(0x000a),
            .length = htons(0x0014),
        },
    };

    char pkt_lcp_1[] = {/* mac */0x74, 0x4d, 0x28, 0x8d, 0x00, 0x31, 0x9c, 0x69, 0xb4, 
    0x61, 0x16, 0xdd, 0x81, 0x00, /* vlan */0x00, 0x02, 0x88, 0x64, /* pppoe hdr */
    0x11, 0x00, 0x00, 0x0a, 0x00, 0x0a, /* ppp protocol */0xc0, 0x21, /* ppp hdr*/
    0x0a, 0x01, 0x00, 0x08, /* magic number */0x01, 0x02, 0x03, 0x04};

    build_echo_reply(buffer, &mulen, &s_ppp_ccb_1);
    assert(mulen == sizeof(pkt_lcp_1));
    assert(memcmp(buffer, pkt_lcp_1, sizeof(pkt_lcp_1)) == 0);

    char pkt_lcp_2[] = {/* mac */0x74, 0x4d, 0x28, 0x8d, 0x00, 0x31, 0x9c, 0x69, 0xb4, 
    0x61, 0x16, 0xdd, 0x81, 0x00, /* vlan */0x00, 0x02, 0x88, 0x64, /* pppoe hdr */
    0x11, 0x00, 0x00, 0x0a, 0x00, 0x0e, /* ppp protocol */0xc0, 0x21, /* ppp hdr*/
    0x0a, 0x01, 0x00, 0x0c, /* magic number */0x01, 0x02, 0x03, 0x04, /* echo 
    requester's magic number */0x05, 0x06, 0x07, 0x08};
    s_ppp_ccb_1.ppp_phase[0].ppp_hdr.length = htons(ntohs(s_ppp_ccb_1.ppp_phase[0].ppp_hdr.length) + 4);

    build_echo_reply(buffer, &mulen, &s_ppp_ccb_1);
    assert(mulen == sizeof(pkt_lcp_2));
    assert(memcmp(buffer, pkt_lcp_2, sizeof(pkt_lcp_2)) == 0);
}

void test_build_auth_request_pap()
{
    U8 buffer[80] = { 0 };
    U16 mulen = 0;

    PPP_INFO_t s_ppp_ccb_1 = {
        .ppp_phase = {{
            .timer_counter = 0,
            .max_retransmit = 10,
            .ppp_payload = (ppp_payload_t) {
                .ppp_protocol = htons(LCP_PROTOCOL),
            },
            .ppp_hdr = (ppp_header_t) {
                .code = CONFIG_REQUEST,
                .identifier = 0x01,
                .length = htons(0x0000),
            },
        },{},},
        .user_num = 1,
        .vlan = 2,
        .PPP_dst_mac = (struct rte_ether_addr){
            .addr_bytes = {0x74, 0x4d, 0x28, 0x8d, 0x00, 0x31},
        },
        .session_id = htons(0x000a),
        .cp = 0,
        .magic_num = htonl(0x01020304),
        .ppp_user_id = (U8 *)"asdf", // 0x61, 0x73, 0x64, 0x66
        .ppp_passwd = (U8 *)"zxcv", // 0x7a, 0x78, 0x63, 0x76
        .identifier = 0xfe,
        .eth_hdr = (struct rte_ether_hdr) {
            .ether_type = htons(VLAN),
        },
        .vlan_header = (vlan_header_t) {
            .tci_union.tci_value = htons(0002),
            .next_proto = htons(ETH_P_PPP_SES),
        },
        .pppoe_header = (pppoe_header_t) {
            .code = 0,
            .ver_type = 0x11,
            .session_id = htons(0x000a),
            .length = htons(0x0000),
        },
    };

    char pkt_lcp_1[] = {/* mac */0x74, 0x4d, 0x28, 0x8d, 0x00, 0x31, 0x9c, 0x69, 0xb4, 
    0x61, 0x16, 0xdd, 0x81, 0x00, /* vlan */0x00, 0x02, 0x88, 0x64, /* pppoe hdr */
    0x11, 0x00, 0x00, 0x0a, 0x00, 0x10, /* ppp protocol */0xc0, 0x23, /* ppp hdr*/
    0x01, 0xfe, 0x00, 0x0e, /* pap user */0x04, 0x61, 0x73, 0x64, 0x66, /* pap passwd */ 
    0x04, 0x7a, 0x78, 0x63, 0x76};

    build_auth_request_pap(buffer, &mulen, &s_ppp_ccb_1);
    assert(mulen == sizeof(pkt_lcp_1));
    assert(memcmp(buffer, pkt_lcp_1, sizeof(pkt_lcp_1)) == 0);

    char pkt_lcp_2[] = {/* mac */0x74, 0x4d, 0x28, 0x8d, 0x00, 0x31, 0x9c, 0x69, 0xb4, 
    0x61, 0x16, 0xdd, 0x81, 0x00, /* vlan */0x00, 0x02, 0x88, 0x64, /* pppoe hdr */
    0x11, 0x00, 0x00, 0x0a, 0x00, 0x20, /* ppp protocol */0xc0, 0x23, /* ppp hdr*/
    0x01, 0xfe, 0x00, 0x1e, /* pap user */0x08, 0x31, 0x71, 0x61, 0x7a, 0x32, 0x77, 
    0x73, 0x78, /* pap passwd */0x10, 0x33, 0x65, 0x64, 0x63, 0x34, 0x72, 0x66, 0x76, 
    0x35, 0x74, 0x67, 0x62, 0x36, 0x79, 0x68, 0x6e};
    s_ppp_ccb_1.ppp_user_id = (U8 *)"1qaz2wsx"; // 0x31, 0x71, 0x61, 0x7a, 0x32, 0x77, 0x73, 0x78
    s_ppp_ccb_1.ppp_passwd = (U8 *)"3edc4rfv5tgb6yhn"; // 0x33, 0x65, 0x64, 0x63, 0x34, 0x72, 0x66, 0x76, 0x35, 0x74, 0x67, 0x62, 0x36, 0x79, 0x68, 0x6e

    build_auth_request_pap(buffer, &mulen, &s_ppp_ccb_1);
    assert(mulen == sizeof(pkt_lcp_2));
    assert(memcmp(buffer, pkt_lcp_2, sizeof(pkt_lcp_2)) == 0);
}

void test_build_auth_ack_pap()
{
    U8 buffer[80] = { 0 };
    U16 mulen = 0;

    PPP_INFO_t s_ppp_ccb_1 = {
        .ppp_phase = {{
            .timer_counter = 0,
            .max_retransmit = 10,
            .ppp_payload = (ppp_payload_t) {
                .ppp_protocol = htons(LCP_PROTOCOL),
            },
            .ppp_hdr = (ppp_header_t) {
                .code = CONFIG_REQUEST,
                .identifier = 0x01,
                .length = htons(0x0000),
            },
        },{},},
        .user_num = 1,
        .vlan = 2,
        .PPP_dst_mac = (struct rte_ether_addr){
            .addr_bytes = {0x74, 0x4d, 0x28, 0x8d, 0x00, 0x31},
        },
        .session_id = htons(0x000a),
        .cp = 0,
        .magic_num = htonl(0x01020304),
        .ppp_user_id = (U8 *)"asdf", // 0x61, 0x73, 0x64, 0x66
        .ppp_passwd = (U8 *)"zxcv", // 0x7a, 0x78, 0x63, 0x76
        .identifier = 0xfe,
        .eth_hdr = (struct rte_ether_hdr) {
            .ether_type = htons(VLAN),
        },
        .vlan_header = (vlan_header_t) {
            .tci_union.tci_value = htons(0002),
            .next_proto = htons(ETH_P_PPP_SES),
        },
        .pppoe_header = (pppoe_header_t) {
            .code = 0,
            .ver_type = 0x11,
            .session_id = htons(0x000a),
            .length = htons(0x0000),
        },
    };

    char pkt_lcp_1[] = {/* mac */0x74, 0x4d, 0x28, 0x8d, 0x00, 0x31, 0x9c, 0x69, 0xb4, 
    0x61, 0x16, 0xdd, 0x81, 0x00, /* vlan */0x00, 0x02, 0x88, 0x64, /* pppoe hdr */
    0x11, 0x00, 0x00, 0x0a, 0x00, 0x0f, /* ppp protocol */0xc0, 0x23, /* ppp hdr*/
    0x02, 0xfe, 0x00, 0x0d, /* Login ok */0x08, 0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x20, 
    0x6f, 0x6b};

    build_auth_ack_pap(buffer, &mulen, &s_ppp_ccb_1);
    assert(mulen == sizeof(pkt_lcp_1));
    assert(memcmp(buffer, pkt_lcp_1, sizeof(pkt_lcp_1)) == 0);
}
