#include <common.h>
#include <sys/resource.h>
#include "../src/vrg.h"
#include "../src/pppd/codec.h"
#include "../src/dbg.h"
#include "test.h"

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
    codec_init((void *)ccb);
    dbg_init((void *)ccb);
}

int main()
{
    signal(SIGCHLD, SIG_IGN);

    puts("====================start unit tests====================\n");
    init_ccb();
    puts("====================test pppd/codec.c====================");
    test_build_padi();
    test_build_padr();
    test_build_padt();
    test_build_config_request();
    test_build_config_ack();
    test_build_config_nak_rej();
    test_build_terminate_request();
    test_build_terminate_ack();
    test_build_echo_reply();
    test_build_auth_request_pap();
    test_build_auth_ack_pap();
    puts("ok!");

    puts("\nall test successfully");
    puts("====================end of unit tests====================");
}
