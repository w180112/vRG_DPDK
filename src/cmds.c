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
#include <rte_memory.h>
#include <rte_eal.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_launch.h>
#include <rte_log.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_ring.h>
#include <rte_debug.h>
#include <rte_mempool.h>
#include <rte_string_fns.h>

#include <cmdline_rdline.h>
#include <cmdline_parse.h>
#include <cmdline_parse_string.h>
#include <cmdline_socket.h>
#include <cmdline.h>
#include "cmds.h"
#include "pppd.h"
#include "pppoeclient.h"

extern struct rte_ring *rte_ring;

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
	for(int i=0; i<MAX_USER; i++) {
		cmdline_printf(cl,"user %d account is %s, password is %s\n", i, ppp_ports[i].user_id, ppp_ports[i].passwd);
		cmdline_printf(cl,"lan mac addr is %x:%x:%x:%x:%x:%x\n", ppp_ports[i].lan_mac[0], ppp_ports[i].lan_mac[1], ppp_ports[i].lan_mac[2], ppp_ports[i].lan_mac[3], ppp_ports[i].lan_mac[4], ppp_ports[i].lan_mac[5]);
		cmdline_printf(cl,"IP addr is %" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8 "\n", *(((uint8_t *)&(ppp_ports[i].ipv4))), *(((uint8_t *)&(ppp_ports[i].ipv4))+1), *(((uint8_t *)&(ppp_ports[i].ipv4))+2), *(((uint8_t *)&(ppp_ports[i].ipv4))+3));
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
	tPPP_MBX *mail = (tPPP_MBX *)malloc(sizeof(tPPP_MBX));
	cli_to_main_msg_t *msg = (cli_to_main_msg_t *)mail->refp;

    msg->type = CLI_QUIT;
	
	mail->type = IPC_EV_TYPE_CLI;
	mail->len = 1;
	//enqueue cli quit event to main thread
	rte_ring_enqueue_burst(rte_ring,(void **)&mail,1,NULL);
}

cmdline_parse_token_string_t cmd_quit_quit =
	TOKEN_STRING_INITIALIZER(struct cmd_quit_result, quit, "quit");

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
					  //"disconnect to disconnect all sessions\n"
					  "quit to quit entire process\n");
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

/****** CONTEXT (list of instruction) */
cmdline_parse_ctx_t ctx[] = {
		(cmdline_parse_inst_t *)&cmd_info,
		(cmdline_parse_inst_t *)&cmd_quit,
		(cmdline_parse_inst_t *)&cmd_help,
	NULL,
};
