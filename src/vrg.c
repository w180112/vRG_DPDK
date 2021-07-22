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
#include				"fsm.h"
#include 				"dp.h"
#include 				"dbg.h"
#include				"cmds.h"
#include				"init.h"
#include				"dp_flow.h"
#include 				"dhcpd.h"
#include                "pppd.h"

#define 				BURST_SIZE 		32

int                     vrg_loop(void);
BOOL 					is_valid(char *token, char *next);
BOOL 					string_split(char *ori_str, char *str1, char *str2, char split_tok);
int 				    control_plane(void);
void                    link_disconnnect(struct rte_timer *tim, VRG_t *vrg_ccb);
extern int 				timer_loop(__attribute__((unused)) void *arg);

rte_atomic16_t			cp_recv_cums;
struct lcore_map 		lcore;
VRG_t                   vrg_ccb;

int main(int argc, char **argv)
{
	U16 user_id_length, passwd_length;
	
	if (argc < 5) {
		puts("Too less parameter.");
		puts("Type vrg <eal_options>");
		return ERROR;
	}
	int ret = rte_eal_init(argc,argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "rte initlize fail.\n");

	vrg_ccb.fp = fopen("./vrg.log","w+");
	if (vrg_ccb.fp)
        rte_openlog_stream(vrg_ccb.fp);
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
	vrg_ccb.user_count = 0, vrg_ccb.base_vlan = 0;
	{
		char config_list[2][256] = { "UserCount", "BaseVlan" };

		FILE *config = fopen("vRG-setup","r");
    	if (!config) {
        	perror("file doesnt exist");
        	rte_exit(EXIT_FAILURE, "vRG system config file not found.\n");
    	}
		char info[256], title[256], val[256], *strtoul_end_str;
		for(int i=0; fgets(info, 256, config) != NULL; i++) {
        	if (string_split(info, title, val, ' ') == FALSE)
				continue;
			if (strncmp(config_list[0], title, strlen(config_list[0])) == 0) {
				vrg_ccb.user_count = (U16)strtoul(val, &strtoul_end_str, 10);
				continue;
			}
			if (strncmp(config_list[1], title, strlen(config_list[0])) == 0) {
				vrg_ccb.base_vlan = (U16)strtoul(val, &strtoul_end_str, 10);
				continue;
			}
		}
		fclose(config);
	}
	#ifdef _NON_VLAN
	vrg_ccb.user_count = 1;
    vrg_ccb.base_vlan = 2;
	#endif

	if (vrg_ccb.user_count < 1 || vrg_ccb.base_vlan < 2)
		rte_exit(EXIT_FAILURE, "vRG system configuration failed.\n");
	if (vrg_ccb.base_vlan + vrg_ccb.user_count > 4094)
		rte_exit(EXIT_FAILURE, "vRG system configure too many users.\n");

	vrg_ccb.ppp_ccb = mmap(NULL, sizeof(PPP_INFO_t)*vrg_ccb.user_count, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
	if (vrg_ccb.ppp_ccb == MAP_FAILED) { 
		perror("map mem");
		vrg_ccb.ppp_ccb = NULL;
		rte_exit(EXIT_FAILURE, "vRG system mempool init failed.\n");
	}
    vrg_ccb.dhcp_ccb = mmap(NULL, sizeof(dhcp_ccb_t)*vrg_ccb.user_count, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
	if (vrg_ccb.dhcp_ccb == MAP_FAILED) { 
		perror("map mem");
		vrg_ccb.dhcp_ccb = NULL;
		rte_exit(EXIT_FAILURE, "vRG system mempool init failed.\n");
	}
	/*vrg_ccb.ppp_ccb_mp = rte_mempool_create("vrg_ccb.ppp_ccb", 4095, sizeof(PPP_INFO_t), RTE_MEMPOOL_CACHE_MAX_SIZE, 0, NULL, NULL, NULL, NULL, rte_socket_id(), 0);
	if (vrg_ccb.ppp_ccb_mp == NULL)
		rte_exit(EXIT_FAILURE, "vRG system mempool init failed: %s\n", rte_strerror(errno));

	if (rte_mempool_get_bulk(vrg_ccb.ppp_ccb_mp, (void **)&vrg_ccb.ppp_ccb, user_count) < 0)
		rte_exit(EXIT_FAILURE, "vRG system memory allocate from mempool failed: %s\n", rte_strerror(errno));*/
	//vrg_ccb.ppp_ccb = te_malloc(NULL, user_count*sizeof(PPP_INFO_t), 0);
	//if (!vrg_ccb.ppp_ccb)
		//rte_exit(EXIT_FAILURE, "vRG system malloc from hugepage failed.\n");
	rte_prefetch2(&vrg_ccb);
	/* init users and ports info */
	{
		FILE *account = fopen("pap-setup","r");
    	if (!account) {
        	perror("file doesnt exist");
        	rte_exit(EXIT_FAILURE, "PPPoE subscriptor account/password cannot be found\n");
    	}
		char user_info[vrg_ccb.user_count][256], user_name[256], passwd[256];
		U16 user_id = 0;
		for(int i=0; fgets(user_info[i],256,account) != NULL; i++) {
			if (i >= vrg_ccb.user_count)
				break;
        	if (string_split(user_info[i], user_name, passwd, ' ') == FALSE) {
				i--;
				continue;
			}
			if (!is_valid(user_name, passwd)) {
				i--;
				continue;
			}
			user_id_length = strlen(user_name);
			passwd_length = strlen(passwd);
			vrg_ccb.ppp_ccb[user_id].ppp_user_id = (unsigned char *)rte_malloc(NULL,user_id_length+1,0);
			vrg_ccb.ppp_ccb[user_id].ppp_passwd = (unsigned char *)rte_malloc(NULL,passwd_length+1,0);
			rte_memcpy(vrg_ccb.ppp_ccb[user_id].ppp_user_id,user_name,user_id_length);
			rte_memcpy(vrg_ccb.ppp_ccb[user_id].ppp_passwd,passwd,passwd_length);
			vrg_ccb.ppp_ccb[user_id].ppp_user_id[user_id_length] = '\0';
			vrg_ccb.ppp_ccb[user_id].ppp_passwd[passwd_length] = '\0';
			user_id++;
			memset(user_name, 0, 256);
			memset(passwd, 0, 256);
    	}
		if (user_id < vrg_ccb.user_count)
			rte_exit(EXIT_FAILURE, "User account and password not enough.\n");
    	fclose(account);
	}

	rte_eth_macaddr_get(0, &vrg_ccb.hsi_lan_mac);
	rte_eth_macaddr_get(1, &vrg_ccb.hsi_wan_src_mac);

	vrg_ccb.cl = cmdline_stdin_new(ctx, "vRG> ");
	if (vrg_ccb.cl == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create cmdline instance\n");

	ret = sys_init(vrg_ccb.cl);
	if (ret)
		rte_exit(EXIT_FAILURE, "System initiation failed: %s\n", rte_strerror(ret));

	rte_atomic16_init(&cp_recv_cums);

	dhcp_init();
    vrg_ccb.lan_ip = rte_cpu_to_be_32(0xc0a80201);
	if (pppdInit() == ERROR)
		rte_exit(EXIT_FAILURE, "PPP initiation failed\n");
	/* Init the pppoe alive user count */
	vrg_ccb.cur_user = 0;
    vrg_ccb.quit_flag = FALSE;
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
	rte_eal_remote_launch((lcore_function_t *)control_plane,NULL,lcore.ctrl_thread);
	rte_eal_remote_launch((lcore_function_t *)wan_recvd,NULL,lcore.wan_thread);
	rte_eal_remote_launch((lcore_function_t *)downlink,NULL,lcore.down_thread);
	rte_eal_remote_launch((lcore_function_t *)lan_recvd,NULL,lcore.lan_thread);
	rte_eal_remote_launch((lcore_function_t *)uplink,NULL,lcore.up_thread);
	rte_eal_remote_launch((lcore_function_t *)gateway,NULL,lcore.gateway_thread);
	rte_eal_remote_launch((lcore_function_t *)timer_loop,NULL,lcore.timer_thread);

	cmdline_printf(vrg_ccb.cl, "vRG> type ? or help to show all available commands\n");
	cmdline_interact(vrg_ccb.cl);

	rte_eal_mp_wait_lcore();
    return 0;
}

int control_plane(void)
{
	if (vrg_loop() == ERROR)
		return ERROR;
	return 0;
}

/***************************************************************
 * vrg_loop : 
 *
 * purpose: Main event loop.
 ***************************************************************/
int vrg_loop(void)
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
				switch (mail[i]->refp[0]) {
					case CLI_DISCONNECT:
						if (mail[i]->refp[1] == 0) {
							for(int j=0; j<vrg_ccb.user_count; j++) {
								if (vrg_ccb.ppp_ccb[j].phase == END_PHASE) {
									printf("Error! User %u is in init phase\nvRG> ", j + 1);
									continue;
								}
								if (vrg_ccb.ppp_ccb[j].ppp_processing == TRUE) {
									printf("Error! User %u is disconnecting pppoe connection, please wait...\nvRG> ", j + 1);
									continue;
								}
								PPP_bye(&vrg_ccb.ppp_ccb[j]);
							}
						}
						else {
							if (vrg_ccb.ppp_ccb[mail[i]->refp[1]-1].phase == END_PHASE) {
								printf("Error! User %u is in init phase\nvRG> ", mail[i]->refp[1]);
								break;
							}
							if (vrg_ccb.ppp_ccb[mail[i]->refp[1]-1].ppp_processing == TRUE) {
								printf("Error! User %u is disconnecting pppoe connection, please wait...\nvRG> ", mail[i]->refp[1]);	
								break;
							}
							PPP_bye(&vrg_ccb.ppp_ccb[mail[i]->refp[1]-1]);
						}
						break;
					case CLI_CONNECT:
						if (mail[i]->refp[1] == 0) {
							for(int j=0; j<vrg_ccb.user_count; j++) {
								if (vrg_ccb.ppp_ccb[j].phase > END_PHASE) {
									printf("Error! User %u is in a pppoe connection\nvRG> ", j + 1);
									continue;
								}
								vrg_ccb.cur_user++;
								vrg_ccb.ppp_ccb[j].phase = PPPOE_PHASE;
								vrg_ccb.ppp_ccb[j].pppoe_phase.max_retransmit = MAX_RETRAN;
								vrg_ccb.ppp_ccb[j].pppoe_phase.timer_counter = 0;
    							if (build_padi(&(vrg_ccb.ppp_ccb[j].pppoe),&(vrg_ccb.ppp_ccb[j])) == FALSE)
									PPP_bye(&(vrg_ccb.ppp_ccb[j]));
								/* set ppp starting boolean flag to TRUE */
								rte_atomic16_set(&vrg_ccb.ppp_ccb[j].ppp_bool, 1);
    							rte_timer_reset(&(vrg_ccb.ppp_ccb[j].pppoe),rte_get_timer_hz(),PERIODICAL,lcore.timer_thread,(rte_timer_cb_t)build_padi,&(vrg_ccb.ppp_ccb[j]));
							}
						}
						else {
							if (vrg_ccb.ppp_ccb[mail[i]->refp[1]-1].phase > END_PHASE) {
								printf("Error! User %u is in a pppoe connection\nvRG> ", mail[i]->refp[1]);
								break;
							}
							vrg_ccb.cur_user++;
							vrg_ccb.ppp_ccb[mail[i]->refp[1]-1].phase = PPPOE_PHASE;
							vrg_ccb.ppp_ccb[mail[i]->refp[1]-1].pppoe_phase.max_retransmit = MAX_RETRAN;
							vrg_ccb.ppp_ccb[mail[i]->refp[1]-1].pppoe_phase.timer_counter = 0;
    						if (build_padi(&(vrg_ccb.ppp_ccb[mail[i]->refp[1]-1].pppoe), &(vrg_ccb.ppp_ccb[mail[i]->refp[1]-1])) == FALSE)
								PPP_bye(&(vrg_ccb.ppp_ccb[mail[i]->refp[1]-1]));
							/* set ppp starting boolean flag to TRUE */
							rte_atomic16_set(&vrg_ccb.ppp_ccb[mail[i]->refp[1]-1].ppp_bool, 1);
    						rte_timer_reset(&(vrg_ccb.ppp_ccb[mail[i]->refp[1]-1].pppoe),rte_get_timer_hz(),PERIODICAL,lcore.timer_thread,(rte_timer_cb_t)build_padi,&(vrg_ccb.ppp_ccb[mail[i]->refp[1]-1]));
						}
						break;	
					case CLI_DHCP_START:
						if (mail[i]->refp[1] == 0) {
							for(int j=0; j<vrg_ccb.user_count; j++) {
								if (rte_atomic16_read(&vrg_ccb.dhcp_ccb[j].dhcp_bool) == 1) {
									printf("Error! User %u dhcp server is already on\nvRG> ", j);
									continue;
								}
								rte_atomic16_set(&vrg_ccb.dhcp_ccb[j].dhcp_bool, 1);
							}
						}
						else {
							if (rte_atomic16_read(&vrg_ccb.dhcp_ccb[mail[i]->refp[1]-1].dhcp_bool) == 1) {
								printf("Error! User %u dhcp server is already on\nvRG> ", mail[i]->refp[1]);
								break;
							}
							rte_atomic16_set(&vrg_ccb.dhcp_ccb[mail[i]->refp[1]-1].dhcp_bool, 1);
						}
						break;
					case CLI_DHCP_STOP:
						if (mail[i]->refp[1] == 0) {
							for(int j=0; j<vrg_ccb.user_count; j++) {
								if (rte_atomic16_read(&vrg_ccb.dhcp_ccb[j].dhcp_bool) == 0) {
									printf("Error! User %u dhcp server is already off\nvRG> ", j);
									continue;
								}
								rte_atomic16_set(&vrg_ccb.dhcp_ccb[j].dhcp_bool, 0);
							}
						}
						else {
							if (rte_atomic16_read(&vrg_ccb.dhcp_ccb[mail[i]->refp[1]-1].dhcp_bool) == 0) {
								printf("Error! User %u dhcp server is already off\nvRG> ", mail[i]->refp[1]);
								break;
							}
							rte_atomic16_set(&vrg_ccb.dhcp_ccb[mail[i]->refp[1]-1].dhcp_bool, 0);
						}
						break;				
					case CLI_QUIT:
						vrg_ccb.quit_flag = TRUE;
						for(int j=0; j<vrg_ccb.user_count; j++) {
							if (vrg_ccb.ppp_ccb[j].phase == END_PHASE)
								vrg_ccb.cur_user++;
 							PPP_bye(&(vrg_ccb.ppp_ccb[j]));
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
                        rte_timer_reset(&vrg_ccb.link,10*rte_get_timer_hz(),SINGLE,lcore.timer_thread,(rte_timer_cb_t)link_disconnnect, &vrg_ccb);			
					else if (mail[i]->refp[0] == LINK_UP)
						rte_timer_stop(&vrg_ccb.link);
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

BOOL is_valid(char *token, char *next)
{
	for(U32 i=0; i<strlen(token); i++)	{
		if (*(token+i) < 0x30 || (*(token+i) > 0x39 && *(token+i) < 0x40) || (*(token+i) > 0x5B && *(token+i) < 0x60) || *(token+i) > 0x7B) {
			if (*(token+i) != 0x2E)
				return FALSE;
		}
	}
	for(U32 i=0; i<strlen(next); i++) {
		if (*(next+i) < 0x30 || (*(next+i) > 0x39 && *(next+i) < 0x40) || (*(next+i) > 0x5B && *(next+i) < 0x60) || *(next+i) > 0x7B) {
			if (*(next+i) != 0x2E)
				return FALSE;
		}
	}
	return TRUE;
}

BOOL string_split(char *ori_str, char *str1, char *str2, char split_tok)
{
	int i, j;

	if (*ori_str == '\n')
		return FALSE;

	for(i=0; i<strlen(ori_str); i++) {
		if (*(ori_str+i) == '#')
			return FALSE;
		if (*(ori_str+i) == split_tok) {
			*(str1+i) = '\0';
			i++;
			break;	
		}
		*(str1+i) = *(ori_str+i);
	}
	if (i == strlen(ori_str))
		return FALSE;
	for(j=0; *(ori_str+i)!='\n' && i<strlen(ori_str); i++, j++)
		*(str2+j) = *(ori_str+i);
	*(str2+j) = '\0';
	
	return TRUE;
}

void link_disconnnect(struct rte_timer *tim, VRG_t *vrg_ccb)
{
    for(int i=0; i<vrg_ccb->user_count; i++)
        exit_ppp(tim, &vrg_ccb->ppp_ccb[i]);
}