/*\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\
  PPPD.C

    - purpose : for ppp detection
	
  Designed by THE on Jan 14, 2019
/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\*/

#include        		<common.h>
#include 				<rte_eal.h>
#include 				<rte_ethdev.h>
#include 				<rte_cycles.h>
#include 				<rte_lcore.h>
#include 				<rte_timer.h>
#include				<rte_malloc.h>
#include 				<rte_ether.h>
#include 				<rte_log.h>
#include				<eal_private.h>
#include 				<cmdline_rdline.h>
#include 				<cmdline_parse.h>
#include 				<cmdline_parse_string.h>
#include 				<cmdline_socket.h>
#include 				<cmdline.h>
#include 				<linux/ethtool.h>

#include				<rte_memcpy.h>
#include 				<rte_flow.h>
#include				<rte_atomic.h>
#include				<rte_pdump.h>
#include 				"pppd.h"
#include				"fsm.h"
#include 				"dp.h"
#include 				"dbg.h"
#include				"cmds.h"
#include				"init.h"
#include				"dp_flow.h"
#include 				"dhcpd.h"

#define 				BURST_SIZE 		32

BOOL					ppp_testEnable = FALSE;
U32						ppp_interval;
U16						ppp_init_delay;
uint8_t					ppp_max_msg_per_query;

rte_atomic16_t			cp_recv_cums;
uint8_t					vendor_id = 0;

tPPP_PORT				ppp_ports[MAX_USER];

extern int 				timer_loop(__attribute__((unused)) void *arg);
extern int 				rte_ethtool_get_drvinfo(uint16_t port_id, struct ethtool_drvinfo *drvinfo);
extern STATUS			PPP_FSM(struct rte_timer *ppp, tPPP_PORT *port_ccb, U16 event);
BOOL 					is_valid(char *token, char *next);
BOOL 					string_split(char *ori_str, char *str1, char *str2, char split_tok);
void 					PPP_int(void);

struct rte_ether_addr 	wan_mac;
int 					log_type;
FILE 					*fp;
volatile BOOL			/*prompt = FALSE, */quit_flag = FALSE;
struct cmdline 			*cl;

nic_vendor_t vendor[] = {
	{ "mlx5_pci", MLX5 },
	{ "net_ixgbe", IXGBE },
	{ "net_vmxnet3", VMXNET3 },
	{ "net_ixgbe_vf", IXGBEVF },
	{ "net_i40e", I40E },
	{ "net_i40e_vf", I40EVF },
	{ NULL, 0 }
};

struct lcore_map {
	U8 ctrl_thread;
	U8 wan_thread;
	U8 down_thread;
	U8 lan_thread;
	U8 up_thread;
	U8 gateway_thread;
	U8 timer_thread;
};

int main(int argc, char **argv)
{
	uint16_t 				portid;
	uint16_t 				user_id_length, passwd_length;
	struct ethtool_drvinfo 	info;
	struct lcore_map 		lcore;
	
	if (argc < 5) {
		puts("Too less parameter.");
		puts("Type vrg <eal_options>");
		return ERROR;
	}
	int ret = rte_eal_init(argc,argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "rte initlize fail.\n");

	fp = fopen("./vrg.log","w+");
	eal_log_set_default(fp);
	if (rte_lcore_count() < 8)
		rte_exit(EXIT_FAILURE, "We need at least 8 cores.\n");
	if (rte_eth_dev_count_avail() < 2)
		rte_exit(EXIT_FAILURE, "We need at least 2 eth ports.\n");
	
	rte_prefetch2(ppp_ports);
	/* init users and ports info */
	{
		FILE *account = fopen("pap-setup","r");
    	if (!account) {
        	perror("file doesnt exist");
        	rte_exit(EXIT_FAILURE, "PPPoE subscriptor account/password cannot find\n");
    	}
		char user_info[MAX_USER][256], user_name[256], passwd[256];
		uint16_t user_id = 0;
		for(int i=0; fgets(user_info[i],256,account) != NULL; i++) {
        	if (string_split(user_info[i], user_name, passwd, ' ') == FALSE) {
				i--;
				continue;
			}
			if (!is_valid(user_name, passwd)) {
				i--;
				continue;
			}
			rte_eth_macaddr_get(0, &(ppp_ports[user_id].lan_mac));
			user_id_length = strlen(user_name);
			passwd_length = strlen(passwd);
			ppp_ports[user_id].user_id = (unsigned char *)rte_malloc(NULL,user_id_length+1,0);
			ppp_ports[user_id].passwd = (unsigned char *)rte_malloc(NULL,passwd_length+1,0);
			rte_memcpy(ppp_ports[user_id].user_id,user_name,user_id_length);
			rte_memcpy(ppp_ports[user_id].passwd,passwd,passwd_length);
			ppp_ports[user_id].user_id[user_id_length] = '\0';
			ppp_ports[user_id].passwd[passwd_length] = '\0';
			user_id++;
			memset(user_name, 0, 256);
			memset(passwd, 0, 256);
    	}
		if (user_id < MAX_USER)
			rte_exit(EXIT_FAILURE, "User account and password not enough.\n");
    	fclose(account);
	}

	rte_eth_macaddr_get(1, &wan_mac);
	ret = sys_init();
	if (ret) {
		rte_strerror(ret);
		rte_exit(EXIT_FAILURE, "System initiation failed\n");
	}

	/* Initialize all ports. */
	//uint32_t lcore_id = 2;
	RTE_ETH_FOREACH_DEV(portid) {
		memset(&info, 0, sizeof(info));
		if (rte_ethtool_get_drvinfo(portid, &info)) {
			printf("Error getting info for port %i\n", portid);
			return -1;
		}
		for(int i=0; vendor[i].vendor; i++) {
			if (strcmp((const char *)info.driver, vendor[i].vendor) == 0) {
				vendor_id = vendor[i].vendor_id;
				break;
			}
		}

		printf("vRG> Port %i driver: %s (ver: %s)\n", portid, info.driver, info.version);
		printf("vRG> firmware-version: %s\n", info.fw_version);
		printf("vRG> bus-info: %s\n", info.bus_info);

		if (PPP_PORT_INIT(portid/*, lcore_id*/) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8 "\n",portid);
		//lcore_id += 2;
	}

	/* init structures */
	for(int i=0; i<MAX_USER; i++) {
		rte_timer_init(&(ppp_ports[i].pppoe));
		rte_timer_init(&(ppp_ports[i].ppp));
		rte_timer_init(&(ppp_ports[i].nat));
		ppp_ports[i].data_plane_start = FALSE;
		rte_atomic16_init(&ppp_ports[i].dhcp_bool);
	}

	rte_atomic16_init(&cp_recv_cums);

	dhcp_init();

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
	lcore.ctrl_thread = rte_get_next_lcore(-1, 1, 0);
	lcore.wan_thread = rte_get_next_lcore(lcore.ctrl_thread, 1, 0);
	lcore.down_thread = rte_get_next_lcore(lcore.wan_thread, 1, 0);
	lcore.lan_thread = rte_get_next_lcore(lcore.down_thread, 1, 0);
	lcore.up_thread = rte_get_next_lcore(lcore.lan_thread, 1, 0);
	lcore.gateway_thread = rte_get_next_lcore(lcore.up_thread, 1, 0);
	lcore.timer_thread = rte_get_next_lcore(lcore.gateway_thread, 1, 0);
	rte_eal_remote_launch((lcore_function_t *)control_plane,NULL,lcore.ctrl_thread);
	rte_eal_remote_launch((lcore_function_t *)wan_recvd,NULL,lcore.wan_thread);
	rte_eal_remote_launch((lcore_function_t *)downlink,NULL,lcore.down_thread);
	rte_eal_remote_launch((lcore_function_t *)lan_recvd,NULL,lcore.lan_thread);
	rte_eal_remote_launch((lcore_function_t *)uplink,NULL,lcore.up_thread);
	rte_eal_remote_launch((lcore_function_t *)gateway,NULL,lcore.gateway_thread);
	rte_eal_remote_launch((lcore_function_t *)timer_loop,NULL,lcore.timer_thread);
	
	//while(prompt == FALSE);
	sleep(1);
	puts("type ? or help to show all available commands");
	cl = cmdline_stdin_new(ctx, "vRG> ");
	if (cl == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create cmdline instance\n");
	cmdline_interact(cl);

	rte_eal_mp_wait_lcore();
    return 0;
}

int control_plane(void)
{
	if (pppdInit() == ERROR)
		return ERROR;
	if (ppp_init() == ERROR)
		return ERROR;
	return 0;
}

/*---------------------------------------------------------
 * ppp_ter : signal handler for SIGTERM only
 *--------------------------------------------------------*/
void PPP_ter(void)
{
	tPPP_MBX *mail = (tPPP_MBX *)rte_malloc(NULL,sizeof(tPPP_MBX),0);

    mail->refp[0] = CLI_QUIT;
	
	mail->type = IPC_EV_TYPE_CLI;
	mail->len = 1;
	//enqueue cli quit event to main thread
	rte_ring_enqueue_burst(rte_ring,(void **)&mail,1,NULL);
}

void PPP_bye(tPPP_PORT *port_ccb)
{
	static U8 total_user = MAX_USER;

   	switch(port_ccb->phase) {
		case END_PHASE:
			if (quit_flag == TRUE) {
				if ((--total_user) == 0) {
					rte_ring_free(rte_ring);
					rte_ring_free(uplink_q);
					rte_ring_free(downlink_q);
					rte_ring_free(gateway_q);
            		fclose(fp);
					cmdline_stdin_exit(cl);
					#ifdef RTE_LIBRTE_PDUMP
					/*uninitialize packet capture framework */
					rte_pdump_uninit();
					#endif
					puts("Bye!");
					exit(0);
				}
			}
			break;
   		case PPPOE_PHASE:
    		break;
    	case LCP_PHASE:
    		port_ccb->cp = 0;
    		PPP_FSM(&(port_ccb->ppp),port_ccb,E_CLOSE);
    		break;
    	case DATA_PHASE:
    		port_ccb->phase--;
    		port_ccb->data_plane_start = FALSE;
    	case IPCP_PHASE:
    		port_ccb->cp = 1;
    		PPP_FSM(&(port_ccb->ppp),port_ccb,E_CLOSE);
    		break;
    	default:
    		;
    }
}

/*---------------------------------------------------------
 * ppp_int : signal handler for INTR-C only
 *--------------------------------------------------------*/
void PPP_int(void)
{
    printf("pppoe client interupt!\n");
	//rte_free(wan_mac);
    rte_ring_free(rte_ring);
	rte_ring_free(uplink_q);
	rte_ring_free(downlink_q);
	rte_ring_free(gateway_q);
    fclose(fp);
	cmdline_stdin_exit(cl);
	printf("bye!\n");
	exit(0);
}

/**************************************************************
 * pppdInit: 
 *
 **************************************************************/
int pppdInit(void)
{	
	ppp_interval = (uint32_t)(3*SECOND); 
    
    //--------- default of all ports ----------
    for(int i=0; i<MAX_USER; i++) {
		ppp_ports[i].ppp_phase[0].state = S_INIT;
		ppp_ports[i].ppp_phase[1].state = S_INIT;
		ppp_ports[i].pppoe_phase.active = FALSE;
		ppp_ports[i].user_num = i;
		ppp_ports[i].vlan = i + BASE_VLAN_ID;
		
		ppp_ports[i].ipv4 = 0;
		ppp_ports[i].ipv4_gw = 0;
		ppp_ports[i].primary_dns = 0;
		ppp_ports[i].second_dns = 0;
		ppp_ports[i].phase = END_PHASE;
		ppp_ports[i].is_pap_auth = TRUE;
		ppp_ports[i].lan_ip = rte_cpu_to_be_32(0xc0a80201);
		for(int j=0; j<TOTAL_SOCK_PORT; j++) {
			rte_atomic16_init(&ppp_ports[i].addr_table[j].is_alive);
			rte_atomic16_init(&ppp_ports[i].addr_table[j].is_fill);
		}
		rte_ether_addr_copy(&wan_mac, &(ppp_ports[i].src_mac));
		memset(ppp_ports[i].dst_mac.addr_bytes, 0, ETH_ALEN);
	}
    
	sleep(1);
	DBG_vRG(DBGPPP,NULL,"============ pppoe init successfully ==============\n");
	return 0;
}
            
/***************************************************************
 * pppd : 
 *
 ***************************************************************/
int ppp_init(void)
{
	uint8_t 			total_user = MAX_USER;
	tPPP_MBX			*mail[BURST_SIZE];
	int 				cp;
	uint16_t			event, session_index = 0;
	uint16_t			burst_size;
	uint16_t			recv_type;
	struct rte_ether_hdr eth_hdr;
	vlan_header_t		vlan_header;
	pppoe_header_t 		pppoe_header;
	ppp_payload_t		ppp_payload;
	ppp_header_t		ppp_hdr;
	ppp_options_t		*ppp_options = (ppp_options_t *)rte_malloc(NULL,40*sizeof(char),0);
#if 0	
	for(int i=0; i<MAX_USER; i++) {
		ppp_ports[i].phase = PPPOE_PHASE;
		ppp_ports[i].pppoe_phase.max_retransmit = MAX_RETRAN;
		ppp_ports[i].pppoe_phase.timer_counter = 0;
    	if (build_padi(&(ppp_ports[i].pppoe),&(ppp_ports[i])) == FALSE)
    		PPP_bye(&(ppp_ports[i]));
    	rte_timer_reset(&(ppp_ports[i].pppoe),rte_get_timer_hz(),PERIODICAL,TIMER_LOOP_LCORE,(rte_timer_cb_t)build_padi,&(ppp_ports[i]));
    }
#endif
	for(;;) {
		burst_size = control_plane_dequeue(mail);
		rte_atomic16_add(&cp_recv_cums,burst_size);
		if (rte_atomic16_read(&cp_recv_cums) > 32)
			rte_atomic16_sub(&cp_recv_cums,32);
		for(int i=0; i<burst_size; i++) {
	    	recv_type = *(uint16_t *)mail[i];
			switch(recv_type) {
			case IPC_EV_TYPE_TMR:
				break;
			case IPC_EV_TYPE_DRV:
#pragma GCC diagnostic push  // require GCC 4.6
#pragma GCC diagnostic ignored "-Wstrict-aliasing"
				session_index = ((vlan_header_t *)(((struct rte_ether_hdr *)mail[i]->refp) + 1))->tci_union.tci_value;
				session_index = rte_be_to_cpu_16(session_index);
				session_index = (session_index & 0xFFF) - BASE_VLAN_ID;
				if (session_index >= MAX_USER) {
					#ifdef _DP_DBG
					puts("Recv not our PPPoE packet.\nDiscard.");
					#endif
					continue;
				}
#pragma GCC diagnostic pop   // require GCC 4.6
				if (PPP_decode_frame(mail[i],&eth_hdr,&vlan_header,&pppoe_header,&ppp_payload,&ppp_hdr,ppp_options,&event,&(ppp_ports[session_index].ppp),&ppp_ports[session_index]) == FALSE)					
					continue;
				if (vlan_header.next_proto == rte_cpu_to_be_16(ETH_P_PPP_DIS)) {
					switch(pppoe_header.code) {
					case PADO:
						if (ppp_ports[session_index].pppoe_phase.active == TRUE)
							continue;
						ppp_ports[session_index].pppoe_phase.active = TRUE;
    					ppp_ports[session_index].pppoe_phase.eth_hdr = &eth_hdr;
						ppp_ports[session_index].pppoe_phase.vlan_header = &vlan_header;
						ppp_ports[session_index].pppoe_phase.pppoe_header = &pppoe_header;
						ppp_ports[session_index].pppoe_phase.pppoe_header_tag = (pppoe_header_tag_t *)((pppoe_header_t *)((vlan_header_t *)((struct rte_ether_hdr *)mail[i]->refp + 1) + 1) + 1);
						ppp_ports[session_index].pppoe_phase.max_retransmit = MAX_RETRAN;
						ppp_ports[session_index].pppoe_phase.timer_counter = 0;
						rte_timer_stop(&(ppp_ports[session_index].pppoe));
						rte_ether_addr_copy(&eth_hdr.d_addr, &ppp_ports[session_index].src_mac);
						rte_ether_addr_copy(&eth_hdr.s_addr, &ppp_ports[session_index].dst_mac);
						if (build_padr(&(ppp_ports[session_index].pppoe),&(ppp_ports[session_index])) == FALSE)
							goto out;
						rte_timer_reset(&(ppp_ports[session_index].pppoe),rte_get_timer_hz(),PERIODICAL,TIMER_LOOP_LCORE,(rte_timer_cb_t)build_padr,&(ppp_ports[session_index]));
						continue;
					case PADS:
						rte_timer_stop(&(ppp_ports[session_index].pppoe));
						ppp_ports[session_index].session_id = pppoe_header.session_id;
						ppp_ports[session_index].cp = 0;
    					for (int i=0; i<2; i++) {
    						ppp_ports[session_index].ppp_phase[i].eth_hdr = &eth_hdr;
							ppp_ports[session_index].ppp_phase[i].vlan_header = &vlan_header;
    						ppp_ports[session_index].ppp_phase[i].pppoe_header = &pppoe_header;
    						ppp_ports[session_index].ppp_phase[i].ppp_payload = &ppp_payload;
    						ppp_ports[session_index].ppp_phase[i].ppp_hdr = &ppp_hdr;
    						ppp_ports[session_index].ppp_phase[i].ppp_options = ppp_options;
   						}
    					PPP_FSM(&(ppp_ports[session_index].ppp),&ppp_ports[session_index],E_OPEN);
						continue;
					case PADT:
						for(session_index=0; session_index<MAX_USER; session_index++) {
							if (ppp_ports[session_index].session_id == pppoe_header.session_id)
								break;
    					}
    					if (session_index == MAX_USER) {
							RTE_LOG(INFO,EAL,"Out of range session id in PADT.\n");
							#ifdef _DP_DBG
    						puts("Out of range session id in PADT.");
							#endif
    						continue;
    					}
    					ppp_ports[session_index].pppoe_phase.eth_hdr = &eth_hdr;
						ppp_ports[session_index].pppoe_phase.pppoe_header = &pppoe_header;
						ppp_ports[session_index].pppoe_phase.pppoe_header_tag = (pppoe_header_tag_t *)((pppoe_header_t *)((struct rte_ether_hdr *)mail[i]->refp + 1) + 1);
						ppp_ports[session_index].pppoe_phase.max_retransmit = MAX_RETRAN;
						
						#ifdef _DP_DBG
						printf("Session 0x%x connection disconnected.\n", rte_be_to_cpu_16(ppp_ports[session_index].session_id));
						#endif
						RTE_LOG(INFO,EAL,"Session 0x%x connection disconnected.\n",rte_be_to_cpu_16(ppp_ports[session_index].session_id));
						ppp_ports[session_index].phase = END_PHASE;
						ppp_ports[session_index].pppoe_phase.active = FALSE;
						rte_timer_stop(&(ppp_ports[session_index].ppp));
						rte_timer_stop(&(ppp_ports[session_index].pppoe));
						if (quit_flag == TRUE) {
							if ((--total_user) == 0) {
                            	rte_ring_free(rte_ring);
								rte_ring_free(uplink_q);
								rte_ring_free(downlink_q);
								rte_ring_free(gateway_q);
                            	fclose(fp);
								cmdline_stdin_exit(cl);
								exit(0);
							}
						}
						continue;		
					case PADM:
						RTE_LOG(INFO,EAL,"recv active discovery message\n");
						continue;
					default:
						RTE_LOG(INFO,EAL,"Unknown PPPoE discovery type %x.\n", pppoe_header.code);
						#ifdef _DP_DBG
						puts("Unknown PPPoE discovery type.");
						#endif
						continue;
					}
				}
				ppp_ports[session_index].ppp_phase[0].ppp_options = ppp_options;
				ppp_ports[session_index].ppp_phase[1].ppp_options = ppp_options;
				if (ppp_payload.ppp_protocol == rte_cpu_to_be_16(AUTH_PROTOCOL)) {
					if (ppp_hdr.code == AUTH_NAK)
						goto out;
					else if (ppp_hdr.code == AUTH_ACK) {
						ppp_ports[session_index].cp = 1;
						PPP_FSM(&(ppp_ports[session_index].ppp),&ppp_ports[session_index],E_OPEN);
						continue;
					}
				}
				cp = (ppp_payload.ppp_protocol == rte_cpu_to_be_16(IPCP_PROTOCOL)) ? 1 : 0;
				ppp_ports[session_index].cp = cp;
				PPP_FSM(&(ppp_ports[session_index].ppp),&ppp_ports[session_index],event);
				break;
			case IPC_EV_TYPE_CLI:
				switch (mail[i]->refp[0]) {
					case CLI_DISCONNECT:
						if (mail[i]->refp[1] == 0) {
							for(int j=0; j<MAX_USER; j++) {
								ppp_ports[j].phase--;
    							ppp_ports[j].data_plane_start = FALSE;
    							ppp_ports[j].cp = 1;
    							PPP_FSM(&(ppp_ports[j].ppp), &ppp_ports[j], E_CLOSE);
							}
						}
						else {
							ppp_ports[mail[i]->refp[1]-1].phase--;
    						ppp_ports[mail[i]->refp[1]-1].data_plane_start = FALSE;
    						ppp_ports[mail[i]->refp[1]-1].cp = 1;
    						PPP_FSM(&(ppp_ports[mail[i]->refp[1]-1].ppp), &ppp_ports[mail[i]->refp[1]-1], E_CLOSE);
						}
						break;
					case CLI_CONNECT:
						if (mail[i]->refp[1] == 0) {
							for(int j=0; j<MAX_USER; j++) {
								if (ppp_ports[j].phase > END_PHASE) {
									printf("Error! User %u is in a pppoe connection\nvRG> ", j);
									continue;
								}
								ppp_ports[j].phase = PPPOE_PHASE;
								ppp_ports[j].pppoe_phase.max_retransmit = MAX_RETRAN;
								ppp_ports[j].pppoe_phase.timer_counter = 0;
    							if (build_padi(&(ppp_ports[j].pppoe),&(ppp_ports[j])) == FALSE)
    								PPP_bye(&(ppp_ports[j]));
    							rte_timer_reset(&(ppp_ports[j].pppoe),rte_get_timer_hz(),PERIODICAL,TIMER_LOOP_LCORE,(rte_timer_cb_t)build_padi,&(ppp_ports[j]));
							}
						}
						else {
							if (ppp_ports[mail[i]->refp[1]-1].phase > END_PHASE) {
								printf("Error! User %u is in a pppoe connection\nvRG> ", mail[i]->refp[1]);
								break;
							}
							ppp_ports[mail[i]->refp[1]-1].phase = PPPOE_PHASE;
							ppp_ports[mail[i]->refp[1]-1].pppoe_phase.max_retransmit = MAX_RETRAN;
							ppp_ports[mail[i]->refp[1]-1].pppoe_phase.timer_counter = 0;
    						if (build_padi(&(ppp_ports[mail[i]->refp[1]-1].pppoe), &(ppp_ports[mail[i]->refp[1]-1])) == FALSE)
    							PPP_bye(&(ppp_ports[mail[i]->refp[1]-1]));
    						rte_timer_reset(&(ppp_ports[mail[i]->refp[1]-1].pppoe),rte_get_timer_hz(),PERIODICAL,TIMER_LOOP_LCORE,(rte_timer_cb_t)build_padi,&(ppp_ports[mail[i]->refp[1]-1]));
						}
						break;	
					case CLI_DHCP_START:
						if (mail[i]->refp[1] == 0) {
							for(int j=0; j<MAX_USER; j++) {
								if (rte_atomic16_read(&ppp_ports[j].dhcp_bool) == 1) {
									printf("Error! User %u dhcp server is already on\nvRG> ", j);
									continue;
								}
								rte_atomic16_set(&ppp_ports[j].dhcp_bool, 1);
							}
						}
						else {
							if (rte_atomic16_read(&ppp_ports[mail[i]->refp[1]-1].dhcp_bool) == 1) {
								printf("Error! User %u dhcp server is already on\nvRG> ", mail[i]->refp[1]);
								break;
							}
							rte_atomic16_set(&ppp_ports[mail[i]->refp[1]-1].dhcp_bool, 1);
						}
						break;
					case CLI_DHCP_STOP:
						if (mail[i]->refp[1] == 0) {
							for(int j=0; j<MAX_USER; j++) {
								if (rte_atomic16_read(&ppp_ports[j].dhcp_bool) == 0) {
									printf("Error! User %u dhcp server is already off\nvRG> ", j);
									continue;
								}
								rte_atomic16_set(&ppp_ports[j].dhcp_bool, 0);
							}
						}
						else {
							if (rte_atomic16_read(&ppp_ports[mail[i]->refp[1]-1].dhcp_bool) == 0) {
								printf("Error! User %u dhcp server is already on\nvRG> ", mail[i]->refp[1]);
								break;
							}
							rte_atomic16_set(&ppp_ports[mail[i]->refp[1]-1].dhcp_bool, 0);
						}
						break;				
					case CLI_QUIT:
						quit_flag = TRUE;
						for(int j=0; j<MAX_USER; j++)
 							PPP_bye(&(ppp_ports[j]));
						break;
					default:
						;
				}
				rte_atomic16_dec(&cp_recv_cums);
				rte_free(mail[i]);
				break;
			case IPC_EV_TYPE_REG:
				if (mail[i]->refp[0] == LINK_DOWN) {
					for(int i=0; i<MAX_USER; i++) {
						ppp_ports[i].cp = 0;
						PPP_FSM(&(ppp_ports[i].ppp),&ppp_ports[i],E_DOWN);
						ppp_ports[i].cp = 1;
						PPP_FSM(&(ppp_ports[i].ppp),&ppp_ports[i],E_DOWN);
					}
				}
				else if (mail[i]->refp[0] == LINK_UP) {
					for(int i=0; i<MAX_USER; i++) {
						ppp_ports[i].cp = 0;
						PPP_FSM(&(ppp_ports[i].ppp),&ppp_ports[i],E_UP);
					}
				}
				rte_free(mail[i]);
				break;
			default:
		    	;
			}
			mail[i] = NULL;
		}
    }
out:
	kill(getpid(), SIGINT);
	return ERROR;
}

BOOL is_valid(char *token, char *next)
{
	for(uint32_t i=0; i<strlen(token); i++)	{
		if (*(token+i) < 0x30 || (*(token+i) > 0x39 && *(token+i) < 0x40) || (*(token+i) > 0x5B && *(token+i) < 0x60) || *(token+i) > 0x7B) {
			if (*(token+i) != 0x2E)
				return FALSE;
		}
	}
	for(uint32_t i=0; i<strlen(next); i++) {
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
