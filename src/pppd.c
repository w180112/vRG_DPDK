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
#include 				"pppd.h"
#include				"fsm.h"
#include 				"dpdk_send_recv.h"
#include 				"dbg.h"
#include				"cmds.h"

#define 				RING_SIZE 		16384
#define 				NUM_MBUFS 		8191
#define 				MBUF_CACHE_SIZE 512
#define 				BURST_SIZE 		32

BOOL					ppp_testEnable = FALSE;
U32						ppp_interval;
U16						ppp_init_delay;
uint8_t					ppp_max_msg_per_query;

uint8_t					cp_recv_cums = 0, cp_recv_prod = 0;
uint8_t					vendor_id = 0;

tPPP_PORT				ppp_ports[MAX_USER]; //port is 1's based

struct rte_mempool 		*mbuf_pool;
struct rte_ring 		*rte_ring, *decap_udp, *decap_tcp, *encap_udp, *encap_tcp;

extern int 				timer_loop(__attribute__((unused)) void *arg);
extern int 				rte_ethtool_get_drvinfo(uint16_t port_id, struct ethtool_drvinfo *drvinfo);
extern STATUS			PPP_FSM(struct rte_timer *ppp, tPPP_PORT *port_ccb, U16 event);
BOOL 					is_valid(char *token, char *next);

unsigned char 			*wan_mac;
int 					log_type;
FILE 					*fp;
volatile BOOL			prompt = FALSE, signal_term = FALSE;
struct cmdline 			*cl;

nic_vendor_t vendor[] = {
	{ "net_mlx5", MLX5 },
	{ "net_ixgbe", IXGBE },
	{ "net_vmxnet3", VMXNET3 },
	{ "net_ixgbevf", IXGBEVF },
	{ NULL, 0 }
};

int main(int argc, char **argv)
{
	uint16_t 				portid;
	uint16_t 				user_id_length, passwd_length;
	struct ethtool_drvinfo 	info;
	
	if (argc < 5) {
		puts("Too less parameter.");
		puts("Type ./pppoeclient <eal_options>");
		return ERROR;
	}
	int ret = rte_eal_init(argc,argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "rte initlize fail.");

	fp = fopen("./pppoeclient.log","w+");
	eal_log_set_default(fp);
	if (rte_lcore_count() < 9)
		rte_exit(EXIT_FAILURE, "We need at least 9 cores.\n");
	if (rte_eth_dev_count_avail() < 2)
		rte_exit(EXIT_FAILURE, "We need at least 2 eth ports.\n");
	
	rte_prefetch2(ppp_ports);
	/* init users and ports info */
	{
		FILE *account = fopen("pap-setup","r");
    	if (!account) {
        	perror("file doesnt exist");
        	return -1;
    	}
		char tok[] = " ", user_info[MAX_USER][256];
		uint16_t user_id = 0;
		for(int i=0; fgets(user_info[i],256,account) != NULL; i++) {
       		char *token, *next;
        	token=strtok_r(user_info[i],tok,&next);
        	if (!next)
				continue;
			if (!is_valid(token,next))
				continue;
			rte_eth_macaddr_get(0,(struct rte_ether_addr *)ppp_ports[user_id].lan_mac);
			user_id_length = strlen(token);
			passwd_length = strlen(next) - 1;
			ppp_ports[user_id].user_id = (unsigned char *)rte_malloc(NULL,user_id_length+1,0);
			ppp_ports[user_id].passwd = (unsigned char *)rte_malloc(NULL,passwd_length+1,0);
			rte_memcpy(ppp_ports[user_id].user_id,token,user_id_length);
			rte_memcpy(ppp_ports[user_id].passwd,next,passwd_length);
			ppp_ports[user_id].user_id[user_id_length] = '\0';
			ppp_ports[user_id].passwd[passwd_length] = '\0';
			user_id++;
    	}
		if (user_id < MAX_USER)
			rte_exit(EXIT_FAILURE, "User account and password not enough.");
    	fclose(account);
	}
	wan_mac = (unsigned char *)rte_malloc(NULL,ETH_ALEN,0);
	rte_eth_macaddr_get(1,(struct rte_ether_addr *)wan_mac);

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
	rte_ring = rte_ring_create("state_machine",RING_SIZE,rte_socket_id(),0);
	decap_tcp = rte_ring_create("decapsulation_tcp",RING_SIZE,rte_socket_id(),0);
	decap_udp = rte_ring_create("decapsulation_udp",RING_SIZE,rte_socket_id(),0);
	encap_tcp = rte_ring_create("encapsulation_tcp",RING_SIZE,rte_socket_id(),0);
	encap_udp = rte_ring_create("encapsulation_udp",RING_SIZE,rte_socket_id(),0);

	/* Initialize all ports. */
	RTE_ETH_FOREACH_DEV(portid) {
		memset(&info, 0, sizeof(info));
		if (rte_ethtool_get_drvinfo(portid, &info)) {
			printf("Error getting info for port %i\n", portid);
			return -1;
		}
		for(int i=0; !vendor[i].vendor; i++) {
			if (strcmp((const char *)info.driver,vendor[i].vendor) == 0) {
				vendor_id = vendor[i].vendor_id;
				break;
			}
		}
		#ifdef _DP_DBG
		printf("Port %i driver: %s (ver: %s)\n", portid, info.driver, info.version);
		printf("firmware-version: %s\n", info.fw_version);
		printf("bus-info: %s\n", info.bus_info);
		#endif
		if (PPP_PORT_INIT(portid) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8 "\n",portid);
	}

	//signal(SIGTERM,(__sighandler_t)PPP_bye);
	signal(SIGINT,(__sighandler_t)PPP_int);

	/* init RTE timer library */
	rte_timer_subsystem_init();

	/* init timer structures */
	for(int i=0; i<MAX_USER; i++) {
		rte_timer_init(&(ppp_ports[i].pppoe));
		rte_timer_init(&(ppp_ports[i].ppp));
		rte_timer_init(&(ppp_ports[i].nat));
		ppp_ports[i].data_plane_start = FALSE;
	}
	
	rte_eal_remote_launch((lcore_function_t *)ppp_recvd,NULL,1);
	rte_eal_remote_launch((lcore_function_t *)decapsulation_tcp,NULL,2);
	rte_eal_remote_launch((lcore_function_t *)decapsulation_udp,NULL,3);
	rte_eal_remote_launch((lcore_function_t *)timer_loop,NULL,4);
	rte_eal_remote_launch((lcore_function_t *)gateway,NULL,5);
	rte_eal_remote_launch((lcore_function_t *)encapsulation_tcp,NULL,6);
	rte_eal_remote_launch((lcore_function_t *)encapsulation_udp,NULL,7);
	rte_eal_remote_launch((lcore_function_t *)control_plane,NULL,8);
	
	while(prompt == FALSE);
	sleep(1);
	puts("type ? or help to show all available commands");
	cl = cmdline_stdin_new(ctx, "\npppoeclient> ");
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
 * ppp_bye : signal handler for SIGTERM only
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
    printf("bye!\n");
	signal_term = TRUE;
   	switch(port_ccb->phase) {
   		case PPPOE_PHASE:
			rte_free(wan_mac);
           	rte_ring_free(rte_ring);
			rte_ring_free(decap_tcp);
			rte_ring_free(decap_udp);
			rte_ring_free(encap_tcp);
			rte_ring_free(encap_udp);
            fclose(fp);
			cmdline_stdin_exit(cl);
			exit(0);
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
	rte_free(wan_mac);
    rte_ring_free(rte_ring);
	rte_ring_free(decap_tcp);
	rte_ring_free(decap_udp);
	rte_ring_free(encap_tcp);
	rte_ring_free(encap_udp);
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
	ppp_interval = (uint32_t)(3*SEC); 
    
    //--------- default of all ports ----------
    for(int i=0; i<MAX_USER; i++) {
		ppp_ports[i].ppp_phase[0].state = S_INIT;
		ppp_ports[i].ppp_phase[1].state = S_INIT;
		ppp_ports[i].user_num = i;
		ppp_ports[i].vlan = i + 1;
		
		ppp_ports[i].ipv4 = 0;
		ppp_ports[i].ipv4_gw = 0;
		ppp_ports[i].primary_dns = 0;
		ppp_ports[i].second_dns = 0;
		ppp_ports[i].phase = END_PHASE;
		ppp_ports[i].is_pap_auth = TRUE;
		memcpy(ppp_ports[i].src_mac,wan_mac,ETH_ALEN);
		memset(ppp_ports[i].dst_mac,0,ETH_ALEN);
	}
    
	sleep(1);
	DBG_PPP(DBGLVL1,NULL,"============ pppoe init successfully ==============\n");
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
	ppp_header_t		ppp_lcp;
	ppp_options_t		*ppp_options = (ppp_options_t *)rte_malloc(NULL,40*sizeof(char),0);
	
	for(int i=0; i<MAX_USER; i++) {
		ppp_ports[i].phase = PPPOE_PHASE;
		ppp_ports[i].pppoe_phase.max_retransmit = MAX_RETRAN;
		ppp_ports[i].pppoe_phase.timer_counter = 0;
    	if (build_padi(&(ppp_ports[i].pppoe),&(ppp_ports[i])) == FALSE)
    		PPP_bye(&(ppp_ports[i]));
    	rte_timer_reset(&(ppp_ports[i].pppoe),rte_get_timer_hz(),PERIODICAL,4,(rte_timer_cb_t)build_padi,&(ppp_ports[i]));
    }
	for(;;) {
		burst_size = control_plane_dequeue(mail);
		cp_recv_cums += burst_size;
		if (cp_recv_cums > 32)
			cp_recv_cums -= 32;
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
				session_index = (session_index & 0xFFF) - 1;
				if (session_index >= MAX_USER) {
					#ifdef _DP_DBG
					puts("Recv not our PPPoE packet.\nDiscard.");
					#endif
					continue;
				}
#pragma GCC diagnostic pop   // require GCC 4.6
				if (PPP_decode_frame(mail[i],&eth_hdr,&vlan_header,&pppoe_header,&ppp_payload,&ppp_lcp,ppp_options,&event,&(ppp_ports[session_index].ppp),&ppp_ports[session_index]) == FALSE)					
					continue;
				if (vlan_header.next_proto == rte_cpu_to_be_16(ETH_P_PPP_DIS)) {
					switch(pppoe_header.code) {
					case PADO:
						for(session_index=0; session_index<MAX_USER; session_index++) {
							int j;
							for(j=0; j<ETH_ALEN; j++) {
								if (ppp_ports[session_index].dst_mac[j] != 0)
									break;
							}
							if (j == ETH_ALEN)
								break;
    					}
    					if (session_index >= MAX_USER) {
							RTE_LOG(INFO,EAL,"Too many pppoe users.\nDiscard.\n");
							#ifdef _DP_DBG
    						puts("Too many pppoe users.\nDiscard.");
							#endif
    						continue;
    					}
    					ppp_ports[session_index].pppoe_phase.eth_hdr = &eth_hdr;
						ppp_ports[session_index].pppoe_phase.vlan_header = &vlan_header;
						ppp_ports[session_index].pppoe_phase.pppoe_header = &pppoe_header;
						ppp_ports[session_index].pppoe_phase.pppoe_header_tag = (pppoe_header_tag_t *)((pppoe_header_t *)((vlan_header_t *)((struct rte_ether_hdr *)mail[i]->refp + 1) + 1) + 1);
						ppp_ports[session_index].pppoe_phase.max_retransmit = MAX_RETRAN;
						ppp_ports[session_index].pppoe_phase.timer_counter = 0;
						rte_timer_stop(&(ppp_ports[session_index].pppoe));
						rte_memcpy(ppp_ports[session_index].src_mac,eth_hdr.d_addr.addr_bytes,ETH_ALEN);
						rte_memcpy(ppp_ports[session_index].dst_mac,eth_hdr.s_addr.addr_bytes,ETH_ALEN);
						if (build_padr(&(ppp_ports[session_index].pppoe),&(ppp_ports[session_index])) == FALSE)
							goto out;
						rte_timer_reset(&(ppp_ports[session_index].pppoe),rte_get_timer_hz(),PERIODICAL,4,(rte_timer_cb_t)build_padr,&(ppp_ports[session_index]));
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
    						ppp_ports[session_index].ppp_phase[i].ppp_lcp = &ppp_lcp;
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
						if ((--total_user) == 0 && signal_term == TRUE) {
							rte_free(wan_mac);
                            rte_ring_free(rte_ring);
							rte_ring_free(decap_tcp);
							rte_ring_free(decap_udp);
							rte_ring_free(encap_tcp);
							rte_ring_free(encap_udp);
                            fclose(fp);
							cmdline_stdin_exit(cl);
							exit(0);
						}
						continue;		
					case PADM:
						RTE_LOG(INFO,EAL,"recv active discovery message\n");
						continue;
					default:
						RTE_LOG(INFO,EAL,"Unknown PPPoE discovery type.\n");
						#ifdef _DP_DBG
						puts("Unknown PPPoE discovery type.");
						#endif
						continue;
					}
				}
				ppp_ports[session_index].ppp_phase[0].ppp_options = ppp_options;
				ppp_ports[session_index].ppp_phase[1].ppp_options = ppp_options;
				if (ppp_payload.ppp_protocol == rte_cpu_to_be_16(AUTH_PROTOCOL)) {
					if (ppp_lcp.code == AUTH_NAK)
						goto out;
					else if (ppp_lcp.code == AUTH_ACK) {
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
					/* TODO: user disconnect and connect command */
					#if 0
					case CLI_DISCONNECT:
						if (mail[i]->refp[1] == CLI_DISCONNECT_ALL) {
							for(int i=0; i<MAX_USER; i++) {
								ppp_ports[i].phase--;
    							ppp_ports[i].data_plane_start = FALSE;
    							ppp_ports[i].cp = 1;
    							PPP_FSM(&(ppp_ports[i].ppp),&ppp_ports[i],E_CLOSE);
							}
						}
						else {
							ppp_ports[mail[i]->refp[1]].phase--;
    						ppp_ports[mail[i]->refp[1]].data_plane_start = FALSE;
    						ppp_ports[mail[i]->refp[1]].cp = 1;
    						PPP_FSM(&(ppp_ports[mail[i]->refp[1]].ppp),&ppp_ports[mail[i]->refp[1]],E_CLOSE);
						}
						break;
					case CLI_CONNECT:
						break;
					#endif
					case CLI_QUIT:
						for(int i=0; i<MAX_USER; i++) {
 							PPP_bye(&(ppp_ports[i])); 
 						}
						break;
					default:
						;
				}
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
	for(uint i=0; i<strlen(token); i++)	{
		if (*(token+i) < 0x30 || (*(token+i) > 0x39 && *(token+i) < 0x41) || (*(token+i) > 0x5B && *(token+i) < 0x60) || *(token+i) > 0x7B)
			return FALSE;
	}
	for(uint i=0; i<strlen(next)-1; i++)	{
		if (*(next+i) < 0x30 || (*(next+i) > 0x39 && *(next+i) < 0x41) || (*(next+i) > 0x5B && *(next+i) < 0x60) || *(next+i) > 0x7B)
			return FALSE;
	}
	return TRUE;
}
