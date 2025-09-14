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
#include <rte_debug.h>
#include <rte_mempool.h>
#include <rte_string_fns.h>
#include <rte_byteorder.h>

#include <cmdline_rdline.h>
#include <cmdline_parse.h>
#include <cmdline_parse_string.h>
#include <cmdline_socket.h>
#include <cmdline.h>

#include <pppd/pppd.h>
#include <pppd/header.h>
#include <dhcpd/dhcp_codec.h>
#include <init.h>
#include <vrg.h>
#include <utils.h>

#include <grpc/grpc.h>

#include "../grpc/vrg_grpc_client.h"

#define PARSE_DELIMITER	" \f\n\r\t\v"

/**********************************************************/

struct cmd_info_result {
	cmdline_fixed_string_t info_token;
	cmdline_fixed_string_t subsystem;
};

static void cmd_info_parsed(void *parsed_result,
		struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	struct cmd_info_result *res = parsed_result;

	if (strncmp(res->subsystem, "hsi", 3) == 0)
		vrg_grpc_get_hsi_info();
	else if (strncmp(res->subsystem, "dhcp", 4) == 0)
		vrg_grpc_get_dhcp_info();
	else if (strncmp(res->subsystem, "system", 6) == 0)
		vrg_grpc_get_system_info();

	return;
}

cmdline_parse_token_string_t cmd_info_info_token =
	TOKEN_STRING_INITIALIZER(struct cmd_info_result, info_token, "show");
cmdline_parse_token_string_t cmd_show_subsystem =
	TOKEN_STRING_INITIALIZER(struct cmd_info_result, subsystem, "hsi#dhcp#system");

cmdline_parse_inst_t cmd_info = {
	.f = cmd_info_parsed,  /* function to call */
	.data = NULL,      /* 2nd arg of func */
	.help_str = "show user info, show <hsi|dhcp|system>",
	.tokens = {        /* token list, NULL terminated */
			(void *)&cmd_info_info_token,
			(void *)&cmd_show_subsystem,
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
#if 0
	char log_buf[256];

	while (fgets(log_buf, 256, vrg_ccb->fp) != NULL)
        cmdline_printf(cl, "%s", log_buf);
#endif
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
    cmdline_stdin_exit(cl);
	exit(0);
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
					  "show <hsi|dhcp|system> to show information\n"
					  "help to show usage commands\n"
					  "disconnect <user id | all> [force] to disconnect session(s)\n"
					  "connect <user id | all> to connect session(s)\n"
					  "dhcp-server <start | stop> <user id | all> to start/stop dhcp server function\n"
					  "quit/exit to quit vRG CLI\n");
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
	cmdline_multi_string_t user_id_opt;
};

static void cmd_connect_parsed(void *parsed_result,
			    __attribute__((unused)) struct cmdline *cl,
			    __attribute__((unused)) void *data)
{
	struct cmd_connect_result *res = parsed_result;
	char *user_id_opt = res->user_id_opt;
	U8 user_id;

	char *user_id_str = strtok_r(user_id_opt, PARSE_DELIMITER, &user_id_opt);
	if (user_id_str == NULL) {
		cmdline_printf(cl, "user id input error\n");
		return;
	}

	if (strcmp(user_id_str, "all") == 0) {
		user_id = 0;
	} else {
		user_id = strtoul(user_id_str, NULL, 10);
		if (user_id <= 0) {
			cmdline_printf(cl, "Wrong user id\n");
			return;
		}
	}

	if (strcmp(res->connect, "connect") == 0) {
		vrg_grpc_hsi_connect(user_id);
	} else {
		char *is_force = strtok_r(user_id_opt, PARSE_DELIMITER, &user_id_opt);
		if (is_force == NULL) {
			vrg_grpc_hsi_disconnect(user_id, false);
			return;
		}
		if (strcmp(is_force, "force") != 0) {
			cmdline_printf(cl, "Wrong disconnect option\n");
			return;
		}
		vrg_grpc_hsi_disconnect(user_id, true);
	}
}

cmdline_parse_token_string_t cmd_connect_connect =
	TOKEN_STRING_INITIALIZER(struct cmd_connect_result, connect, "connect#disconnect");
cmdline_parse_token_string_t cmd_connect_user_id_opt =
	TOKEN_STRING_INITIALIZER(struct cmd_connect_result, user_id_opt, TOKEN_STRING_MULTI);

cmdline_parse_inst_t cmd_connect = {
	.f = cmd_connect_parsed,  /* function to call */
	.data = NULL,      /* 2nd arg of func */
	.help_str = "start/stop pppoe connection, "
			"connect|disconnect <user id | all> [force]",
	.tokens = {        /* token list, NULL terminated */
		(void *)&cmd_connect_connect,
		(void *)&cmd_connect_user_id_opt,
		NULL,
	},
};

/**********************************************************/

struct cmd_dhcp_result {
	cmdline_fixed_string_t dhcp;
	cmdline_fixed_string_t cmd;
	cmdline_fixed_string_t user_id;
};

static void cmd_dhcp_parsed(void *parsed_result,
			    __attribute__((unused)) struct cmdline *cl,
			    __attribute__((unused)) void *data)
{
	struct cmd_dhcp_result *res = parsed_result;
	U8 user_id;
	
	if (strcmp(res->user_id, "all") == 0) {
		user_id = 0;
	} else {
		user_id = strtoul(res->user_id, NULL, 10);
		if (user_id <= 0) {
			cmdline_printf(cl, "Wrong user id\n");
			return;
		}
	}

	if (strcmp(res->cmd, "start") == 0) {
		vrg_grpc_dhcp_server_start(user_id);
	} else if (strcmp(res->cmd, "stop") == 0) {
		vrg_grpc_dhcp_server_stop(user_id);
	} else {
		cmdline_printf(cl, "Wrong dhcp cmd\n");
		return;
	}
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

int main(int argc, char **argv)
{
	grpc_init();
	vrg_grpc_client_connect("unix:///var/run/vrg/vrg.sock");
	//vrg_grpc_client_connect("127.0.0.1:50051");

	struct cmdline *cl = cmdline_stdin_new(ctx, "vRG>");
	if (cl == NULL)
		return -1;

	cmdline_interact(cl);

	cmdline_stdin_exit(cl);
	grpc_shutdown();
	return 0;
}
