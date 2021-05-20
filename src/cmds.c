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
#include <rte_malloc.h>
#include <rte_branch_prediction.h>
#include <rte_launch.h>
#include <rte_log.h>
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
#include "pppd.h"
#include "pppoeclient.h"
#include "dhcp_codec.h"

extern struct rte_ring *rte_ring;
extern nic_vendor_t 	vendor[];
extern uint8_t			vendor_id;
extern dhcp_ccb_t 		dhcp_ccb[MAX_USER];

typedef struct cli_to_main_msg {
	uint8_t type;
	uint8_t user_id;
}cli_to_main_msg_t;

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

	if (vendor_id == 0)
		cmdline_printf(cl,"We are using unexcepted driver\n");
	else {
		for(int i=0; vendor[i].vendor!=NULL; i++) {
			if (vendor_id == vendor[i].vendor_id) {
				cmdline_printf(cl,"We are using %s driver\n", vendor[i].vendor);
				break;
			}
		}
	}
	
	rte_eth_stats_get(0, &ethdev_stat);
	cmdline_printf(cl, "LAN port total rx %" PRIu64 " pkts, tx %" PRIu64 " pkts. ", ethdev_stat.ipackets, ethdev_stat.opackets);
	cmdline_printf(cl, "Rx %" PRIu64 " bytes, tx %" PRIu64 " bytes. ", ethdev_stat.ibytes, ethdev_stat.obytes);
	cmdline_printf(cl, "Rx drops %" PRIu64 " pkts.\n", ethdev_stat.imissed);
	rte_eth_stats_get(1, &ethdev_stat);
	cmdline_printf(cl, "WAN port total rx %" PRIu64 " pkts, tx %" PRIu64 " pkts. ", ethdev_stat.ipackets, ethdev_stat.opackets);
	cmdline_printf(cl, "Rx %" PRIu64 " bytes, tx %" PRIu64 " bytes. ", ethdev_stat.ibytes, ethdev_stat.obytes);
	cmdline_printf(cl, "Rx drops %" PRIu64 " pkts.\n", ethdev_stat.imissed);

	for(int i=0; i<MAX_USER; i++) {
		switch (ppp_ports[i].phase) {
		case END_PHASE:
			cmdline_printf(cl, "User %d is in init phase\n", i + 1);
			break;
		case PPPOE_PHASE:
			cmdline_printf(cl, "User %d is in pppoe phase\n", i + 1);
			break;
		case LCP_PHASE:
			cmdline_printf(cl, "User %d is in lcp phase\n", i + 1);
			break;
		case AUTH_PHASE:
			cmdline_printf(cl, "User %d is in auth phase\n", i + 1);
			break;
		case IPCP_PHASE:
			cmdline_printf(cl, "User %d is in ipcp phase\n", i + 1);
			break;
		case DATA_PHASE:
			cmdline_printf(cl, "User %d is in PPPoE connection\n", i + 1);
			cmdline_printf(cl, "User %d account is %s, password is %s\n", i + 1, ppp_ports[i].user_id, ppp_ports[i].passwd);
			#ifdef _NON_VLAN
			cmdline_printf(cl, "Session ID is 0x%x\n", rte_be_to_cpu_16(ppp_ports[i].session_id));
			#else
			cmdline_printf(cl, "Session ID is 0x%x, VLAN ID is 0x%x\n", rte_be_to_cpu_16(ppp_ports[i].session_id), ppp_ports[i].vlan);
			#endif
			cmdline_printf(cl, "WAN IP addr is %" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8 "\n", *(((U8 *)&(ppp_ports[i].ipv4))), *(((U8 *)&(ppp_ports[i].ipv4))+1), *(((U8 *)&(ppp_ports[i].ipv4))+2), *(((U8 *)&(ppp_ports[i].ipv4))+3));
			break;
		default:
			break;
		}

		cmdline_printf(cl, "WAN mac addr is %x:%x:%x:%x:%x:%x\n", ppp_ports[i].src_mac.addr_bytes[0], ppp_ports[i].src_mac.addr_bytes[1], ppp_ports[i].src_mac.addr_bytes[2], ppp_ports[i].src_mac.addr_bytes[3], ppp_ports[i].src_mac.addr_bytes[4], ppp_ports[i].src_mac.addr_bytes[5]);
		cmdline_printf(cl, "LAN mac addr is %x:%x:%x:%x:%x:%x\n", ppp_ports[i].lan_mac.addr_bytes[0], ppp_ports[i].lan_mac.addr_bytes[1], ppp_ports[i].lan_mac.addr_bytes[2], ppp_ports[i].lan_mac.addr_bytes[3], ppp_ports[i].lan_mac.addr_bytes[4], ppp_ports[i].lan_mac.addr_bytes[5]);
		if (rte_atomic16_read(&ppp_ports[i].dhcp_bool) == 1) 
			cmdline_printf(cl, "DHCP server is on and IP addr is %" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8 "\n", (rte_be_to_cpu_32(dhcp_ccb[i].dhcp_server_ip) & 0xff000000) >> 24, (rte_be_to_cpu_32(dhcp_ccb[i].dhcp_server_ip) & 0x00ff0000) >> 16, (rte_be_to_cpu_32(dhcp_ccb[i].dhcp_server_ip) & 0x0000ff00) >> 8, rte_be_to_cpu_32(dhcp_ccb[i].dhcp_server_ip) & 0x000000ff);
		else if (rte_atomic16_read(&ppp_ports[i].dhcp_bool) == 0)
			cmdline_printf(cl, "DHCP server is off\n");
		for(U8 j=0; j<MAX_IP_POOL; j++) {
			if (dhcp_ccb[i].ip_pool[j].used) {
				rte_ether_format_addr(buf, 18, &dhcp_ccb[i].ip_pool[j].mac_addr);
				cmdline_printf(cl, "DHCP ip pool index %" PRIu8 " IP addr %" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8 " is used by %s\n", j, (rte_be_to_cpu_32(dhcp_ccb[i].ip_pool[j].ip_addr) & 0xff000000) >> 24, (rte_be_to_cpu_32(dhcp_ccb[i].ip_pool[j].ip_addr) & 0x00ff0000) >> 16, (rte_be_to_cpu_32(dhcp_ccb[i].ip_pool[j].ip_addr) & 0x0000ff00) >> 8, rte_be_to_cpu_32(dhcp_ccb[i].ip_pool[j].ip_addr) & 0x000000ff, buf);
			}
		}
		cmdline_printf(cl, "================================================================================\n");
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

struct cmd_quit_result {
	cmdline_fixed_string_t quit;
};

static void cmd_quit_parsed(__attribute__((unused)) void *parsed_result,
			    __attribute__((unused)) struct cmdline *cl,
			    __attribute__((unused)) void *data)
{
	tPPP_MBX *mail = (tPPP_MBX *)rte_malloc(NULL,sizeof(tPPP_MBX),0);
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
					  "dhcp <start | stop> <user id | all> to start/stop dhcp server function\n"
					  "quit/exit to quit entire process\n");
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
	tPPP_MBX *mail = (tPPP_MBX *)rte_malloc(NULL,sizeof(tPPP_MBX),0);
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
			rte_free(mail);
			return;
		}
	}
	
	if (msg->user_id > MAX_USER) {
		printf("Too large user id\nvRG> ");
		rte_free(mail);
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
	tPPP_MBX *mail = (tPPP_MBX *)rte_malloc(NULL,sizeof(tPPP_MBX),0);
	cli_to_main_msg_t *msg = (cli_to_main_msg_t *)mail->refp;

	if (strcmp(res->cmd, "start") == 0)
		msg->type = CLI_DHCP_START;
	else if (strcmp(res->cmd, "stop") == 0)
		msg->type = CLI_DHCP_STOP;
	else {
		printf("Wrong dhcp cmd\nvRG> ");
		rte_free(mail);
		return;
	}
    
	if (strcmp(res->user_id, "all") == 0)
		msg->user_id = 0;
	else {
		msg->user_id = strtoul(res->user_id, NULL, 10);
		if (msg->user_id <= 0) {
			printf("Wrong user id\nvRG> ");
			rte_free(mail);
			return;
		}
	}
	
	if (msg->user_id > MAX_USER) {
		printf("Too large user id\nvRG> ");
		rte_free(mail);
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
	NULL,
};
