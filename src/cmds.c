/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <inttypes.h>
#include <stdio.h>
#include <termios.h>
#include <errno.h>
#include <sys/queue.h>

#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_memory.h>
#include <rte_eal.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_launch.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_ring.h>
#include <rte_debug.h>
#include <rte_mempool.h>
#include <rte_string_fns.h>
#include <rte_byteorder.h>

#include <cmdline_rdline.h>
#include <cmdline_parse.h>
#include <cmdline_parse_string.h>
#include <cmdline_socket.h>
#include <cmdline.h>
#include "cmds.h"
#include "pppd/pppd.h"
#include "pppd/header.h"
#include "dhcpd/dhcp_codec.h"
#include "init.h"
#include "vrg.h"
#include "utils.h"

extern struct rte_ring *rte_ring;
typedef struct cli_to_main_msg {
	U8 type;
	U8 user_id;
}cli_to_main_msg_t;
static VRG_t *vrg_ccb;

/**********************************************************/

struct cmd_info_result {
	cmdline_fixed_string_t info_token;
};

static void cmd_info_parsed(__attribute__((unused)) void *parsed_result,
		struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	char buf[64];
	struct rte_eth_stats ethdev_stat;
	dhcp_ccb_t *dhcp_ccb = vrg_ccb->dhcp_ccb;

	if (vrg_ccb->nic_info.vendor_id == 0)
		cmdline_printf(cl,"We are using unexcepted driver\n");
	else {
		cmdline_printf(cl,"We are using %s driver\n", vrg_ccb->nic_info.vendor_name);
	}
	
	rte_eth_stats_get(0, &ethdev_stat);
	cmdline_printf(cl, "LAN port total rx %" PRIu64 " pkts, tx %" PRIu64 " pkts. ", ethdev_stat.ipackets, ethdev_stat.opackets);
	cmdline_printf(cl, "Rx %" PRIu64 " bytes, tx %" PRIu64 " bytes. ", ethdev_stat.ibytes, ethdev_stat.obytes);
	cmdline_printf(cl, "Rx drops %" PRIu64 " pkts.\n", ethdev_stat.imissed);
	rte_eth_stats_get(1, &ethdev_stat);
	cmdline_printf(cl, "WAN port total rx %" PRIu64 " pkts, tx %" PRIu64 " pkts. ", ethdev_stat.ipackets, ethdev_stat.opackets);
	cmdline_printf(cl, "Rx %" PRIu64 " bytes, tx %" PRIu64 " bytes. ", ethdev_stat.ibytes, ethdev_stat.obytes);
	cmdline_printf(cl, "Rx drops %" PRIu64 " pkts.\n", ethdev_stat.imissed);
	cmdline_printf(cl, "WAN mac addr is %x:%x:%x:%x:%x:%x\n", vrg_ccb->nic_info.hsi_wan_src_mac.addr_bytes[0], vrg_ccb->nic_info.hsi_wan_src_mac.addr_bytes[1], vrg_ccb->nic_info.hsi_wan_src_mac.addr_bytes[2], vrg_ccb->nic_info.hsi_wan_src_mac.addr_bytes[3], vrg_ccb->nic_info.hsi_wan_src_mac.addr_bytes[4], vrg_ccb->nic_info.hsi_wan_src_mac.addr_bytes[5]);
	cmdline_printf(cl, "LAN mac addr is %x:%x:%x:%x:%x:%x\n", vrg_ccb->nic_info.hsi_lan_mac.addr_bytes[0], vrg_ccb->nic_info.hsi_lan_mac.addr_bytes[1], vrg_ccb->nic_info.hsi_lan_mac.addr_bytes[2], vrg_ccb->nic_info.hsi_lan_mac.addr_bytes[3], vrg_ccb->nic_info.hsi_lan_mac.addr_bytes[4], vrg_ccb->nic_info.hsi_lan_mac.addr_bytes[5]);

	for(int i=0; i<vrg_ccb->user_count; i++) {
		cmdline_printf(cl, "================================================================================\n");
		if (vrg_ccb->non_vlan_mode == TRUE)
			cmdline_printf(cl, "User %d is in ", i + 1);
		else
			cmdline_printf(cl, "User %d VLAN ID is %" PRIu16 " and is in ", i + 1, vrg_ccb->ppp_ccb[i].vlan);
		switch (vrg_ccb->ppp_ccb[i].phase) {
		case END_PHASE:
			cmdline_printf(cl, "init phase\n");
			break;
		case PPPOE_PHASE:
			cmdline_printf(cl, "pppoe phase\n");
			break;
		case LCP_PHASE:
			cmdline_printf(cl, "lcp phase\n");
			break;
		case AUTH_PHASE:
			cmdline_printf(cl, "auth phase\n");
			break;
		case IPCP_PHASE:
			cmdline_printf(cl, "ipcp phase\n");
			break;
		case DATA_PHASE:
			cmdline_printf(cl, "PPPoE connection\n");
			cmdline_printf(cl, "PPP account is %s, password is %s\n", vrg_ccb->ppp_ccb[i].ppp_user_id, vrg_ccb->ppp_ccb[i].ppp_passwd);
			cmdline_printf(cl, "Session ID is 0x%x\n", rte_be_to_cpu_16(vrg_ccb->ppp_ccb[i].session_id));
			cmdline_printf(cl, "WAN IP addr is %" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8 "\n", *(((U8 *)&(vrg_ccb->ppp_ccb[i].hsi_ipv4))), *(((U8 *)&(vrg_ccb->ppp_ccb[i].hsi_ipv4))+1), *(((U8 *)&(vrg_ccb->ppp_ccb[i].hsi_ipv4))+2), *(((U8 *)&(vrg_ccb->ppp_ccb[i].hsi_ipv4))+3));
			break;
		default:
			break;
		}

		if (rte_atomic16_read(&vrg_ccb->dhcp_ccb[i].dhcp_bool) == 1) {
			cmdline_printf(cl, "DHCP server is on and IP addr is %" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8 "\n", (rte_be_to_cpu_32(dhcp_ccb[i].dhcp_server_ip) & 0xff000000) >> 24, (rte_be_to_cpu_32(dhcp_ccb[i].dhcp_server_ip) & 0x00ff0000) >> 16, (rte_be_to_cpu_32(dhcp_ccb[i].dhcp_server_ip) & 0x0000ff00) >> 8, rte_be_to_cpu_32(dhcp_ccb[i].dhcp_server_ip) & 0x000000ff);
			for(U8 j=0; j<MAX_IP_POOL; j++) {
				if (dhcp_ccb[i].ip_pool[j].used) {
					rte_ether_format_addr(buf, 18, &dhcp_ccb[i].ip_pool[j].mac_addr);
					cmdline_printf(cl, "DHCP ip pool index %" PRIu8 " IP addr %" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8 " is used by %s\n", j, (rte_be_to_cpu_32(dhcp_ccb[i].ip_pool[j].ip_addr) & 0xff000000) >> 24, (rte_be_to_cpu_32(dhcp_ccb[i].ip_pool[j].ip_addr) & 0x00ff0000) >> 16, (rte_be_to_cpu_32(dhcp_ccb[i].ip_pool[j].ip_addr) & 0x0000ff00) >> 8, rte_be_to_cpu_32(dhcp_ccb[i].ip_pool[j].ip_addr) & 0x000000ff, buf);
				}
			}
		}
		else if (rte_atomic16_read(&vrg_ccb->dhcp_ccb[i].dhcp_bool) == 0)
			cmdline_printf(cl, "DHCP server is off\n");
	}
}

cmdline_parse_token_string_t cmd_info_info_token =
	TOKEN_STRING_INITIALIZER(struct cmd_info_result, info_token, "info");

cmdline_parse_inst_t cmd_info = {
	.f = cmd_info_parsed,  /* function to call */
	.data = NULL,      /* 2nd arg of func */
	.help_str = "show user info",
	.tokens = {        /* token list, NULL terminated */
			(void *)&cmd_info_info_token,
			NULL,
	},
};

/**********************************************************/

struct cmd_log_result {
	cmdline_fixed_string_t log_token;
};

static void cmd_log_parsed(__attribute__((unused)) void *parsed_result,
		struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	char log_buf[256];

	while (fgets(log_buf, 256, vrg_ccb->fp) != NULL)
        cmdline_printf(cl, "%s", log_buf);
    cmdline_printf(cl, "\n");
}

cmdline_parse_token_string_t cmd_log_log_token =
	TOKEN_STRING_INITIALIZER(struct cmd_log_result, log_token, "log");

cmdline_parse_inst_t cmd_log = {
	.f = cmd_log_parsed,  /* function to call */
	.data = NULL,      /* 2nd arg of func */
	.help_str = "show vRG log file",
	.tokens = {        /* token list, NULL terminated */
			(void *)&cmd_log_log_token,
			NULL,
	},
};

/**********************************************************/

struct cmd_quit_result {
	cmdline_fixed_string_t quit;
};

static void cmd_quit_parsed(__attribute__((unused)) void *parsed_result,
			    __attribute__((unused)) struct cmdline *cl,
			    __attribute__((unused)) void *data)
{
    tVRG_MBX *mail = vrg_malloc(tVRG_MBX, sizeof(tVRG_MBX), 0);
	if (mail == NULL) {
		cmdline_printf(cl, "cmd_quit_parsed failed: vrg_malloc failed: %s\n", rte_strerror(rte_errno));
		return;
	}
	cli_to_main_msg_t *msg = (cli_to_main_msg_t *)mail->refp;

    msg->type = CLI_QUIT;
	
	mail->type = IPC_EV_TYPE_CLI;
	mail->len = 1;
	//enqueue cli quit event to main thread
	rte_ring_enqueue_burst(rte_ring,(void **)&mail,1,NULL);
}

cmdline_parse_token_string_t cmd_quit_quit =
	TOKEN_STRING_INITIALIZER(struct cmd_quit_result, quit, "quit#exit");

cmdline_parse_inst_t cmd_quit = {
	.f = cmd_quit_parsed,  /* function to call */
	.data = NULL,      /* 2nd arg of func */
	.help_str = "close the application",
	.tokens = {        /* token list, NULL terminated */
		(void *)&cmd_quit_quit,
		NULL,
	},
};

/**********************************************************/

struct cmd_help_result {
	cmdline_fixed_string_t help;
};

static void cmd_help_parsed(__attribute__((unused)) void *parsed_result,
			    struct cmdline *cl,
			    __attribute__((unused)) void *data)
{
	cmdline_printf(cl,"usage: \n"
		 			  "info is to show all pppoe users' info\n"
					  "help to show usage commands\n"
					  "disconnect <user id | all> to disconnect session(s)\n"
					  "connect <user id | all> to connect session(s)\n"
					  "dhcp-server <start | stop> <user id | all> to start/stop dhcp server function\n"
					  "quit/exit to quit vRG system\n");
}

cmdline_parse_token_string_t cmd_help_help =
	TOKEN_STRING_INITIALIZER(struct cmd_help_result, help, "help");

cmdline_parse_inst_t cmd_help = {
	.f = cmd_help_parsed,  /* function to call */
	.data = NULL,      /* 2nd arg of func */
	.help_str = "show help",
	.tokens = {        /* token list, NULL terminated */
		(void *)&cmd_help_help,
		NULL,
	},
};

/**********************************************************/

struct cmd_connect_result {
	cmdline_fixed_string_t connect;
	cmdline_fixed_string_t user_id;
};

static void cmd_connect_parsed( void *parsed_result,
			    __attribute__((unused)) struct cmdline *cl,
			    __attribute__((unused)) void *data)
{
	struct cmd_connect_result *res = parsed_result;
	tVRG_MBX *mail = vrg_malloc(tVRG_MBX, sizeof(tVRG_MBX), 0);
	if (mail == NULL) {
		cmdline_printf(cl, "cmd_connect_parsed failed: vrg_malloc failed: %s\n", rte_strerror(rte_errno));
		return;
	}
	cli_to_main_msg_t *msg = (cli_to_main_msg_t *)mail->refp;

	if (strcmp(res->connect, "connect") == 0)
		msg->type = CLI_CONNECT;
	else 
		msg->type = CLI_DISCONNECT;
    
	if (strcmp(res->user_id, "all") == 0)
		msg->user_id = 0;
	else {
		msg->user_id = strtoul(res->user_id, NULL, 10);
		if (msg->user_id <= 0) {
			printf("Wrong user id\nvRG> ");
			vrg_mfree(mail);
			return;
		}
	}
	
	if (msg->user_id > vrg_ccb->user_count) {
		printf("Too large user id\nvRG> ");
		vrg_mfree(mail);
		return;
	}

	mail->type = IPC_EV_TYPE_CLI;
	mail->len = sizeof(cli_to_main_msg_t);
	//enqueue cli quit event to main thread
	rte_ring_enqueue_burst(rte_ring,(void **)&mail,1,NULL);
}

cmdline_parse_token_string_t cmd_connect_connect =
	TOKEN_STRING_INITIALIZER(struct cmd_connect_result, connect, "connect#disconnect");
cmdline_parse_token_string_t cmd_connect_user_id =
	TOKEN_STRING_INITIALIZER(struct cmd_connect_result, user_id, NULL);

cmdline_parse_inst_t cmd_connect = {
	.f = cmd_connect_parsed,  /* function to call */
	.data = NULL,      /* 2nd arg of func */
	.help_str = "start/stop pppoe connection",
	.tokens = {        /* token list, NULL terminated */
		(void *)&cmd_connect_connect,
		(void *)&cmd_connect_user_id,
		NULL,
	},
};

/**********************************************************/

struct cmd_dhcp_result {
	cmdline_fixed_string_t dhcp;
	cmdline_fixed_string_t cmd;
	cmdline_fixed_string_t user_id;
};

static void cmd_dhcp_parsed( void *parsed_result,
			    __attribute__((unused)) struct cmdline *cl,
			    __attribute__((unused)) void *data)
{
	struct cmd_dhcp_result *res = parsed_result;
	tVRG_MBX *mail = vrg_malloc(tVRG_MBX, sizeof(tVRG_MBX), 0);
	if (mail == NULL) {
		cmdline_printf(cl, "cmd_dhcp_parsed failed: vrg_malloc failed: %s\n", rte_strerror(rte_errno));
		return;
	}
	cli_to_main_msg_t *msg = (cli_to_main_msg_t *)mail->refp;

	if (strcmp(res->cmd, "start") == 0)
		msg->type = CLI_DHCP_START;
	else if (strcmp(res->cmd, "stop") == 0)
		msg->type = CLI_DHCP_STOP;
	else {
		printf("Wrong dhcp cmd\nvRG> ");
		vrg_mfree(mail);
		return;
	}
    
	if (strcmp(res->user_id, "all") == 0)
		msg->user_id = 0;
	else {
		msg->user_id = strtoul(res->user_id, NULL, 10);
		if (msg->user_id <= 0) {
			printf("Wrong user id\nvRG> ");
			vrg_mfree(mail);
			return;
		}
	}
	
	if (msg->user_id > vrg_ccb->user_count) {
		printf("Too large user id\nvRG> ");
		vrg_mfree(mail);
		return;
	}

	mail->type = IPC_EV_TYPE_CLI;
	mail->len = sizeof(cli_to_main_msg_t);
	//enqueue cli quit event to main thread
	rte_ring_enqueue_burst(rte_ring,(void **)&mail,1,NULL);
}

cmdline_parse_token_string_t cmd_dhcp_dhcp =
	TOKEN_STRING_INITIALIZER(struct cmd_dhcp_result, dhcp, "dhcp-server");
cmdline_parse_token_string_t cmd_dhcp_cmd =
	TOKEN_STRING_INITIALIZER(struct cmd_dhcp_result, cmd, "start#stop");
cmdline_parse_token_string_t cmd_dhcp_user_id =
	TOKEN_STRING_INITIALIZER(struct cmd_dhcp_result, user_id, NULL);

cmdline_parse_inst_t cmd_dhcp = {
	.f = cmd_dhcp_parsed,  /* function to call */
	.data = NULL,      /* 2nd arg of func */
	.help_str = "start/stop dhcp server",
	.tokens = {        /* token list, NULL terminated */
		(void *)&cmd_dhcp_dhcp,
		(void *)&cmd_dhcp_cmd,
		(void *)&cmd_dhcp_user_id,
		NULL,
	},
};

/****** CONTEXT (list of instruction) */
cmdline_parse_ctx_t ctx[] = {
		(cmdline_parse_inst_t *)&cmd_info,
		(cmdline_parse_inst_t *)&cmd_quit,
		(cmdline_parse_inst_t *)&cmd_help,
		(cmdline_parse_inst_t *)&cmd_connect,
		(cmdline_parse_inst_t *)&cmd_dhcp,
		(cmdline_parse_inst_t *)&cmd_log,
	NULL,
};

STATUS init_cli(void *ccb)
{
	vrg_ccb = (VRG_t *)ccb;
	vrg_ccb->cl = cmdline_stdin_new(ctx, "vRG> ");
	if (vrg_ccb->cl == NULL)
		return ERROR;

	return SUCCESS;
}
