#include <common.h>
#include "pppd.h"
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <inttypes.h>

STATUS parse_cmd(char *cmd, size_t cmd_len);

extern tPPP_PORT	ppp_ports[MAX_USER];

static const struct option lgopts[] = {
	{ "user_info", 0, NULL, 'u'},
	{ "help", 0, NULL, 'h'},
	{ NULL, 0, NULL, 0}
};

static const char 	short_options[] =
	"h:"  /* help */
	"u:"  /* pppoe user info */
	;

STATUS parse_cmd(char *cmd, size_t cmd_len)
{

	int opt;
	char argvopt[10][20];
	int option_index, argc = 1;
/* TODO: detect "     " */
	for(uint8_t i=0, k=0; i<cmd_len; i++, k++) {
		if (cmd[i] == ' ') {
			k=0;
			argc++;
			continue;
		}
		if (argc > 10 || k >= 20) {
			puts("Too many cmds/options");
			break;
		}
		argvopt[argc-1][k] = cmd[i]; 
	}

	while ((opt = getopt_long(argc, (char * const *)argvopt, short_options, lgopts, &option_index)) != EOF) {
		switch (opt) {
		case 'h':
			puts("usage: \n"
				 "-u / user_info is to show all pppoe users' info\n"
				 "-h / helpe if to show usage message\n");
			break;
		case 'u':
			for(int i=0; i<MAX_USER; i++) {
				printf("user %d account is %s, password is %s\n", i, ppp_ports[i].user_id, ppp_ports[i].passwd);
				printf("lan mac addr is %x:%x:%x:%x:%x:%x\n", ppp_ports[i].lan_mac[0], ppp_ports[i].lan_mac[1], ppp_ports[i].lan_mac[2], ppp_ports[i].lan_mac[3], ppp_ports[i].lan_mac[4], ppp_ports[i].lan_mac[5]);
				printf("IP addr is %" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8 "\n", *(((uint8_t *)&(ppp_ports[i].ipv4))), *(((uint8_t *)&(ppp_ports[i].ipv4))+1), *(((uint8_t *)&(ppp_ports[i].ipv4))+2), *(((uint8_t *)&(ppp_ports[i].ipv4))+3));
			}
			break;
		/* long options */
		case 0:
			break;

		default:
			puts("usage: \n"
				 "-u is to show all pppoe users' info\n"
				 "-h if to show usage message\n");
			return FALSE;
		}
	}
	return TRUE;
}