#include <assert.h>
#include <stdlib.h>
#include <common.h>
#include "../../src/pppd/codec.h"
#include "../../src/dbg.h"

void init_ccb()
{
    VRG_t *ccb = malloc(sizeof(VRG_t));
    
    ccb->fp = NULL,
    ccb->nic_info = (struct nic_info){
        .hsi_wan_src_mac = {
            .addr_bytes = {0x9c, 0x69, 0xb4, 0x61, 0x16, 0xdd},
        },
        .hsi_lan_mac = {
            .addr_bytes = {0x9c, 0x69, 0xb4, 0x61, 0x16, 0xdc},
        },
    };
    ccb->loglvl = -1;
    codec_init(ccb);
    dbg_init(ccb);
}

void test_build_padi() {
    U8 buffer[80];
    U16 mulen;

    init_ccb();

    PPP_INFO_t s_ppp_ccb_1 = {
        .pppoe_phase = {
            .timer_counter = 0,
            .max_retransmit = 10,
        },
        .user_num = 1,
        .vlan = 2,
    };
    char pkt_1[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x9c, 0x69, 0xb4, 0x61, 
    0x16, 0xdd, 0x81, 0x00, 0x00, 0x02, 0x88, 0x63, 0x11, 0x09, 0x00, 0x00, 0x00, 
    0x04, 0x01, 0x01, 0x00, 0x00};

    assert(build_padi(buffer, &mulen, &s_ppp_ccb_1) == TRUE);
    assert(mulen == sizeof(pkt_1));
    assert(memcmp(buffer, pkt_1, mulen) == 0);

    memset(buffer, 0, sizeof(buffer));
    s_ppp_ccb_1.pppoe_phase.timer_counter = 10;
    assert(build_padi(buffer, &mulen, &s_ppp_ccb_1) == FALSE);
}