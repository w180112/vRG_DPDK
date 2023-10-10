#include        		<common.h>
#include 				<rte_eal.h>
#include 				<rte_ethdev.h>
#include 				<rte_cycles.h>
#include 				<rte_lcore.h>
#include 				<rte_timer.h>
#include				<rte_malloc.h>
#include 				<rte_ether.h>
#include 				<rte_log.h>
#include 				<cmdline_rdline.h>
#include 				<cmdline_parse.h>
#include 				<cmdline_parse_string.h>
#include 				<cmdline_socket.h>
#include 				<cmdline.h>

#include				<rte_memcpy.h>
#include 				<rte_flow.h>
#include				<rte_atomic.h>
#include				<rte_pdump.h>
#include 				<rte_trace.h>
#include 				<sys/mman.h>
#include                "vrg.h"
#include				"pppd/fsm.h"
#include 				"dp.h"
#include 				"dbg.h"
#include				"cmds.h"
#include				"init.h"
#include				"dp_flow.h"
#include 				"dhcpd/dhcpd.h"
#include				"config.h"
#include				"timer.h"

#define 				BURST_SIZE 		32

int                     vrg_loop(VRG_t *vrg_ccb);
int 				    control_plane(VRG_t *vrg_ccb);
void                    link_disconnnect(struct rte_timer *tim, VRG_t *vrg_ccb);

rte_atomic16_t			cp_recv_cums;
struct lcore_map 		lcore;
VRG_t                   vrg_ccb;

int vrg_start(int argc, char **argv)
{	
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "rte initlize fail.\n");

	vrg_ccb.fp = fopen("./vrg.log","w+");
	if (vrg_ccb.fp)
        rte_openlog_stream(vrg_ccb.fp);
	dbg_init(&vrg_ccb);
	if (rte_lcore_count() < 8)
		rte_exit(EXIT_FAILURE, "We need at least 8 cores.\n");
	if (rte_eth_dev_count_avail() < 2)
		rte_exit(EXIT_FAILURE, "We need at least 2 eth ports.\n");
	
	lcore.ctrl_thread = rte_get_next_lcore(rte_lcore_id(), 1, 0);
	lcore.wan_thread = rte_get_next_lcore(lcore.ctrl_thread, 1, 0);
	lcore.down_thread = rte_get_next_lcore(lcore.wan_thread, 1, 0);
	lcore.lan_thread = rte_get_next_lcore(lcore.down_thread, 1, 0);
	lcore.up_thread = rte_get_next_lcore(lcore.lan_thread, 1, 0);
	lcore.gateway_thread = rte_get_next_lcore(lcore.up_thread, 1, 0);
	lcore.timer_thread = rte_get_next_lcore(lcore.gateway_thread, 1, 0);

	if (rte_eth_dev_socket_id(0) > 0 && rte_eth_dev_socket_id(0) != (int)rte_lcore_to_socket_id(lcore.lan_thread))
		printf("WARNING, LAN port is on remote NUMA node to polling thread.\n\tPerformance will not be optimal.\n");
	if (rte_eth_dev_socket_id(1) > 0 && rte_eth_dev_socket_id(1) != (int)rte_lcore_to_socket_id(lcore.wan_thread))
		printf("WARNING, WAN port is on remote NUMA node to polling thread.\n\tPerformance will not be optimal.\n");

	/* Read network config */
	if (parse_config("./config.cfg", &vrg_ccb) != SUCCESS) {
		printf("parse config file error\n");
		return -1;
	}
	VRG_LOG(INFO, vrg_ccb.fp, NULL, NULL, "vRG log level is %s", loglvl2str(vrg_ccb.loglvl));
	if (vrg_ccb.non_vlan_mode != FALSE) {
		vrg_ccb.user_count = 1;
    	vrg_ccb.base_vlan = 2;
	}

	if (vrg_ccb.user_count < 1 || vrg_ccb.base_vlan < 2)
		rte_exit(EXIT_FAILURE, "vRG system configuration failed.\n");
	if (vrg_ccb.base_vlan + vrg_ccb.user_count > 4094)
		rte_exit(EXIT_FAILURE, "vRG system configure too many users.\n");
    
	/*vrg_ccb.ppp_ccb_mp = rte_mempool_create("vrg_ccb.ppp_ccb", 4095, sizeof(PPP_INFO_t), RTE_MEMPOOL_CACHE_MAX_SIZE, 0, NULL, NULL, NULL, NULL, rte_socket_id(), 0);
	if (vrg_ccb.ppp_ccb_mp == NULL)
		rte_exit(EXIT_FAILURE, "vRG system mempool init failed: %s\n", rte_strerror(errno));

	if (rte_mempool_get_bulk(vrg_ccb.ppp_ccb_mp, (void **)&vrg_ccb.ppp_ccb, user_count) < 0)
		rte_exit(EXIT_FAILURE, "vRG system memory allocate from mempool failed: %s\n", rte_strerror(errno));*/
	//vrg_ccb.ppp_ccb = te_malloc(NULL, user_count*sizeof(PPP_INFO_t), 0);
	//if (!vrg_ccb.ppp_ccb)
		//rte_exit(EXIT_FAILURE, "vRG system malloc from hugepage failed.\n");
	/* init users and ports info */

	if (init_cli(&vrg_ccb) == ERROR) {
		VRG_LOG(ERR, vrg_ccb.fp, NULL, NULL, "Cannot create cmdline instance");
		goto err;
	}

	ret = sys_init(&vrg_ccb);
	if (ret) {
		VRG_LOG(ERR, vrg_ccb.fp, NULL, NULL, "System initiation failed: %s", rte_strerror(ret));
		goto rm_cli;
	}

	rte_atomic16_init(&cp_recv_cums);

	if (pppdInit(&vrg_ccb) == ERROR) {
		VRG_LOG(ERR, vrg_ccb.fp, NULL, NULL, "PPP initiation failed");
		goto rm_cli;
	}
	codec_init(&vrg_ccb);
	dhcp_init(&vrg_ccb);
	fsm_init(&vrg_ccb);
	/* Init the pppoe alive user count */
	vrg_ccb.cur_user = 0;
    vrg_ccb.quit_flag = FALSE;
	rte_prefetch2(&vrg_ccb);
	#ifdef RTE_LIBRTE_PDUMP
	/* initialize packet capture framework */
	rte_pdump_init();
	#endif
	#if 0
	struct rte_flow_error error;
	struct rte_flow *flow = generate_flow(0, 1, &error);
	if (!flow) {
		printf("Flow can't be created %d message: %s\n", error.type, error.message ? error.message : "(no stated reason)");
		rte_exit(EXIT_FAILURE, "error in creating flow");
	}
	#endif
	rte_eal_remote_launch((lcore_function_t *)control_plane, (void *)&vrg_ccb, lcore.ctrl_thread);
	rte_eal_remote_launch((lcore_function_t *)wan_recvd, (void *)&vrg_ccb, lcore.wan_thread);
	rte_eal_remote_launch((lcore_function_t *)downlink, (void *)&vrg_ccb, lcore.down_thread);
	rte_eal_remote_launch((lcore_function_t *)lan_recvd, (void *)&vrg_ccb, lcore.lan_thread);
	rte_eal_remote_launch((lcore_function_t *)uplink, (void *)&vrg_ccb, lcore.up_thread);
	rte_eal_remote_launch((lcore_function_t *)gateway, (void *)&vrg_ccb, lcore.gateway_thread);
	rte_eal_remote_launch((lcore_function_t *)timer_loop, (void *)&vrg_ccb, lcore.timer_thread);

	cmdline_printf(vrg_ccb.cl, "vRG> type ? or help to show all available commands\n");
	cmdline_interact(vrg_ccb.cl);

	rte_eal_mp_wait_lcore();
    return 0;

rm_cli:
	cmdline_stdin_exit(vrg_ccb.cl);
err:
	return -1;
}

int control_plane(VRG_t *vrg_ccb)
{
	if (vrg_loop(vrg_ccb) == ERROR)
		return ERROR;
	return 0;
}

/***************************************************************
 * vrg_loop : 
 *
 * purpose: Main event loop.
 ***************************************************************/
int vrg_loop(VRG_t *vrg_ccb)
{
	tVRG_MBX			*mail[BURST_SIZE];
	U16					burst_size;
	U16					recv_type;

	for(;;) {
		burst_size = control_plane_dequeue(mail);
		/* update the ring queue index between hsi_recvd() */
		rte_atomic16_add(&cp_recv_cums,burst_size);
		if (rte_atomic16_read(&cp_recv_cums) > 32)
			rte_atomic16_sub(&cp_recv_cums,32);
		for(int i=0; i<burst_size; i++) {
	    	recv_type = *(U16 *)mail[i];
			switch(recv_type) {
			case IPC_EV_TYPE_TMR:
				break;
			case IPC_EV_TYPE_DRV:
				/* recv pppoe packet from hsi_recvd() */
                if (ppp_process(mail[i]) == FALSE)
                    continue;
				break;
			case IPC_EV_TYPE_CLI:
				/* mail[i]->refp[0] means cli command, mail[i]->refp[1] means user id */
				U8 user_id = mail[i]->refp[1]; //user_id = 0 means all users
				switch (mail[i]->refp[0]) {
					case CLI_DISCONNECT:
						if (user_id == 0) {
							for(int j=0; j<vrg_ccb->user_count; j++) {
								if (vrg_ccb->ppp_ccb[j].phase == END_PHASE) {
									VRG_LOG(ERR, vrg_ccb->fp, &(vrg_ccb->ppp_ccb[j]), PPPLOGMSG, "Error! User %u is in init phase", j + 1);
									continue;
								}
								if (vrg_ccb->ppp_ccb[j].ppp_processing == TRUE) {
									VRG_LOG(ERR, vrg_ccb->fp, &(vrg_ccb->ppp_ccb[j]), PPPLOGMSG, "Error! User %u is disconnecting pppoe connection, please wait...", j + 1);
									continue;
								}
								PPP_bye(&vrg_ccb->ppp_ccb[j]);
							}
						}
						else {
							if (vrg_ccb->ppp_ccb[user_id-1].phase == END_PHASE) {
								VRG_LOG(ERR, vrg_ccb->fp, &(vrg_ccb->ppp_ccb[user_id-1]), PPPLOGMSG, "Error! User %u is in init phase", user_id);
								break;
							}
							if (vrg_ccb->ppp_ccb[user_id-1].ppp_processing == TRUE) {
								VRG_LOG(ERR, vrg_ccb->fp, &(vrg_ccb->ppp_ccb[user_id-1]), PPPLOGMSG, "Error! User %u is disconnecting pppoe connection, please wait...", user_id);	
								break;
							}
							PPP_bye(&vrg_ccb->ppp_ccb[user_id-1]);
						}
						break;
					case CLI_CONNECT:
						if (user_id == 0) {
							for(int j=0; j<vrg_ccb->user_count; j++) {
								if (vrg_ccb->ppp_ccb[j].phase > END_PHASE) {
									VRG_LOG(ERR, vrg_ccb->fp, &(vrg_ccb->ppp_ccb[j]), PPPLOGMSG, "Error! User %u is in a pppoe connection", j + 1);
									continue;
								}
								vrg_ccb->cur_user++;
								vrg_ccb->ppp_ccb[j].phase = PPPOE_PHASE;
								vrg_ccb->ppp_ccb[j].pppoe_phase.max_retransmit = MAX_RETRAN;
								vrg_ccb->ppp_ccb[j].pppoe_phase.timer_counter = 0;
    							if (send_pkt(ENCODE_PADI, &(vrg_ccb->ppp_ccb[j])) == ERROR)
									PPP_bye(&(vrg_ccb->ppp_ccb[j]));
								/* set ppp starting boolean flag to TRUE */
								rte_atomic16_set(&vrg_ccb->ppp_ccb[j].ppp_bool, 1);
    							rte_timer_reset(&(vrg_ccb->ppp_ccb[j].pppoe), rte_get_timer_hz(), PERIODICAL, lcore.timer_thread, (rte_timer_cb_t)A_padi_timer_func, &(vrg_ccb->ppp_ccb[j]));
							}
						}
						else {
							if (vrg_ccb->ppp_ccb[user_id-1].phase > END_PHASE) {
								VRG_LOG(ERR, vrg_ccb->fp, &(vrg_ccb->ppp_ccb[user_id-1]), PPPLOGMSG, "Error! User %u is in a pppoe connection", user_id);
								break;
							}
							vrg_ccb->cur_user++;
							vrg_ccb->ppp_ccb[user_id-1].phase = PPPOE_PHASE;
							vrg_ccb->ppp_ccb[user_id-1].pppoe_phase.max_retransmit = MAX_RETRAN;
							vrg_ccb->ppp_ccb[user_id-1].pppoe_phase.timer_counter = 0;
    						if (send_pkt(ENCODE_PADI, &(vrg_ccb->ppp_ccb[user_id-1])) == ERROR)
								PPP_bye(&(vrg_ccb->ppp_ccb[user_id-1]));
							/* set ppp starting boolean flag to TRUE */
							rte_atomic16_set(&vrg_ccb->ppp_ccb[user_id-1].ppp_bool, 1);
    						rte_timer_reset(&(vrg_ccb->ppp_ccb[user_id-1].pppoe), rte_get_timer_hz(), PERIODICAL, lcore.timer_thread, (rte_timer_cb_t)A_padi_timer_func, &(vrg_ccb->ppp_ccb[user_id-1]));
						}
						break;	
					case CLI_DHCP_START:
						if (user_id == 0) {
							for(int j=0; j<vrg_ccb->user_count; j++) {
								if (rte_atomic16_read(&vrg_ccb->dhcp_ccb[j].dhcp_bool) == 1) {
									VRG_LOG(ERR, vrg_ccb->fp, &(vrg_ccb->dhcp_ccb[j]), DHCPLOGMSG, "Error! User %u dhcp server is already on", j);
									continue;
								}
								rte_atomic16_set(&vrg_ccb->dhcp_ccb[j].dhcp_bool, 1);
							}
						}
						else {
							if (rte_atomic16_read(&vrg_ccb->dhcp_ccb[user_id-1].dhcp_bool) == 1) {
								VRG_LOG(ERR, vrg_ccb->fp, &(vrg_ccb->dhcp_ccb[user_id-1]), DHCPLOGMSG, "Error! User %u dhcp server is already on", user_id);
								break;
							}
							rte_atomic16_set(&vrg_ccb->dhcp_ccb[user_id-1].dhcp_bool, 1);
						}
						break;
					case CLI_DHCP_STOP:
						if (user_id == 0) {
							for(int j=0; j<vrg_ccb->user_count; j++) {
								if (rte_atomic16_read(&vrg_ccb->dhcp_ccb[j].dhcp_bool) == 0) {
									VRG_LOG(ERR, vrg_ccb->fp, &(vrg_ccb->dhcp_ccb[j]), DHCPLOGMSG, "Error! User %u dhcp server is already off", j);
									continue;
								}
								rte_atomic16_set(&vrg_ccb->dhcp_ccb[j].dhcp_bool, 0);
							}
						}
						else {
							if (rte_atomic16_read(&vrg_ccb->dhcp_ccb[user_id-1].dhcp_bool) == 0) {
								VRG_LOG(ERR, vrg_ccb->fp, &(vrg_ccb->dhcp_ccb[user_id-1]), DHCPLOGMSG, "Error! User %u dhcp server is already off", user_id);
								break;
							}
							rte_atomic16_set(&vrg_ccb->dhcp_ccb[user_id-1].dhcp_bool, 0);
						}
						break;				
					case CLI_QUIT:
						vrg_ccb->quit_flag = TRUE;
						for(int j=0; j<vrg_ccb->user_count; j++) {
							if (vrg_ccb->ppp_ccb[j].phase == END_PHASE)
								vrg_ccb->cur_user++;
 							PPP_bye(&(vrg_ccb->ppp_ccb[j]));
						}
						break;
					default:
						;
				}
				rte_atomic16_dec(&cp_recv_cums);
				rte_free(mail[i]);
				break;
			case IPC_EV_TYPE_REG:
                if ((U16)(mail[i]->refp[1]) == 1) {
					if (mail[i]->refp[0] == LINK_DOWN)
                        rte_timer_reset(&vrg_ccb->link,10*rte_get_timer_hz(),SINGLE,lcore.timer_thread,(rte_timer_cb_t)link_disconnnect, &vrg_ccb);			
					else if (mail[i]->refp[0] == LINK_UP)
						rte_timer_stop(&vrg_ccb->link);
				}
				rte_free(mail[i]);
				break;
			default:
		    	;
			}
			mail[i] = NULL;
		}
    }
	return ERROR;
}

void link_disconnnect(struct rte_timer *tim, VRG_t *vrg_ccb)
{
    for(int i=0; i<vrg_ccb->user_count; i++)
        exit_ppp(tim, &vrg_ccb->ppp_ccb[i]);
}