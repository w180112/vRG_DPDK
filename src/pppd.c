/*\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\
  PPPD.C

    - purpose : for ppp detection
	
  Designed by THE on Jan 14, 2019
/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\*/

#include        	<common.h>
#include 			<rte_eal.h>
#include 			<rte_ethdev.h>
#include 			<rte_cycles.h>
#include 			<rte_lcore.h>
#include 			<rte_ether.h>
#include			"fsm.h"
#include 			"dpdk_send_recv.h"

#define 			RING_SIZE 		16384
#define 			NUM_MBUFS 		8191
#define 			MBUF_CACHE_SIZE 512

BOOL				ppp_testEnable=FALSE;
U32					ppp_ttl;
U32					ppp_interval;
U16					ppp_init_delay;
uint8_t				ppp_max_msg_per_query;

U8 					PORT_BIT_MAP(tPPP_PORT ports[]);
tPPP_PORT			ppp_ports[2]; //port is 1's based

tIPC_ID 			pppQid = -1;
tIPC_ID 			pppQid_main = -1;

struct rte_mempool 		*mbuf_pool;
struct rte_ring 		*rte_ring;

uint16_t 				session_id;
unsigned char 			*src_mac;
unsigned char 			*dst_mac;
unsigned char 			*user_id;
unsigned char 			*passwd;

int main(int argc, char **argv)
{
	uint16_t portid;
	
	if (argc < 7) {
		puts("Too less parameter.");
		puts("Type ./pppoeclient <username> <password> <eal_options>");
		return ERROR;
	}

	int ret = rte_eal_init(argc-3,argv+3);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "initlize fail!");

	if (rte_lcore_count() < 4)
		rte_exit(EXIT_FAILURE, "We need at least 4 cores\n");

	src_mac = (unsigned char *)malloc(ETH_ALEN);
	dst_mac = (unsigned char *)malloc(ETH_ALEN);
	user_id = (unsigned char *)malloc(strlen(argv[1]));
	passwd = (unsigned char *)malloc(strlen(argv[2]));
	memcpy(user_id,argv[1],strlen(argv[1]));
	memcpy(passwd,argv[2],strlen(argv[2]));
	
	rte_eth_macaddr_get(1,(struct ether_addr *)src_mac);

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
	rte_ring = rte_ring_create("state_machine",RING_SIZE,rte_socket_id(),0);

	/* Initialize all ports. */
	RTE_ETH_FOREACH_DEV(portid) {
		if (PPP_PORT_INIT(portid) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8 "\n",portid);
	}

	//signal(SIGINT,PPP_bye);

	rte_eal_remote_launch(ppp_recvd,rte_ring,1);
	rte_eal_remote_launch(encapsulation,rte_ring,2);
	rte_eal_remote_launch(control_plane,rte_ring,3);
	//pppoe_cli();
	rte_eal_mp_wait_lcore();
    return 0;
}

int control_plane(void)
{
	if (pppdInit() == ERROR)
		return ERROR;
	if (ppp_init() == ERROR)
		return ERROR;
	kill(getpid(), SIGINT);
	return 0;
}

/*---------------------------------------------------------
 * ppp_bye : signal handler for INTR-C only
 *--------------------------------------------------------*/
void PPP_bye(void)
{
    printf("bye!\n");
    //free(if_name);
    free(src_mac);
    free(dst_mac);
    free(user_id);
    free(passwd);
    rte_ring_free(rte_ring);
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
	ppp_ports[0].enable = TRUE;
	ppp_ports[0].query_cnt = 1;
	ppp_ports[0].state = S_INIT;
	ppp_ports[0].port = 0;
		
	ppp_ports[0].imsg_cnt =
	ppp_ports[0].err_imsg_cnt =
	ppp_ports[0].omsg_cnt = 0;

	ppp_ports[1].enable = TRUE;
	ppp_ports[1].query_cnt = 1;
	ppp_ports[1].state = S_INIT;
	ppp_ports[1].port = 0;
		
	ppp_ports[1].imsg_cnt =
	ppp_ports[1].err_imsg_cnt =
	ppp_ports[1].omsg_cnt = 0;
    
	sleep(1);
	ppp_testEnable = TRUE; //to let driver ppp msg come in ...
	puts("============ pppoe init successfully ==============");
	return 0;
}
            
/***************************************************************
 * pppd : 
 *
 ***************************************************************/
int ppp_init(void)
{
	extern STATUS		PPP_FSM(int cp, tPPP_PORT *port_ccb, U16 event, struct ethhdr *eth_hdr, pppoe_header_t *pppoe_header, ppp_payload_t *ppp_payload, ppp_lcp_header_t *ppp_lcp, ppp_lcp_options_t *ppp_lcp_options);
    tPPP_MBX			*mail;
	tPPP_PORT			*ccb;
	int					cp; //cp is "control protocol", means we need to determine cp after parsing packet
	uint16_t			event;
	uint16_t			burst_size;
	uint16_t			recv_type;
	struct ethhdr 		eth_hdr;
	pppoe_header_t 		pppoe_header;
	ppp_payload_t		ppp_payload;
	ppp_lcp_header_t	ppp_lcp;
	ppp_lcp_options_t	*ppp_lcp_options = (ppp_lcp_options_t *)malloc(40*sizeof(char));
	
    if (build_padi() == FALSE) {
    	free(ppp_lcp_options);
    	return ERROR;
    }
    for(;;) {
    	mail = control_plane_dequeue(mail);
		if (PPP_decode_frame(mail,&eth_hdr,&pppoe_header,&ppp_payload,&ppp_lcp,&ppp_lcp_options,&event) == FALSE)
			continue;
		if (pppoe_recv(mail,&eth_hdr,&pppoe_header) == FALSE)
			continue;
		if (pppoe_header.code == PADS)
			break;
    }
    PPP_FSM(0,&ppp_ports[0],E_OPEN,&eth_hdr,&pppoe_header,&ppp_payload,&ppp_lcp,ppp_lcp_options);
    mail = NULL;
	for(;;){
		mail = control_plane_dequeue(mail);
	    recv_type = *(uint16_t*)mail;
	    
		switch(recv_type){
		case IPC_EV_TYPE_TMR:
			break;
		
		case IPC_EV_TYPE_DRV:
			if (PPP_decode_frame(mail,&eth_hdr,&pppoe_header,&ppp_payload,&ppp_lcp,&ppp_lcp_options,&event) == FALSE) {
				ppp_ports[0].err_imsg_cnt++;
				continue;
			}
			if (ppp_payload.ppp_protocol == htons(AUTH_PROTOCOL)) {
				if (ppp_lcp.code == AUTH_NAK) {
					free(ppp_lcp_options);
					return ERROR;
				}
				else if (ppp_lcp.code == AUTH_ACK) {
					PPP_FSM(1,&ppp_ports[1],E_OPEN,&eth_hdr,&pppoe_header,&ppp_payload,&ppp_lcp,ppp_lcp_options);
					continue;
				}
			}
			if (pppoe_header.code != SESSION_DATA) {
				if (pppoe_recv(mail,&eth_hdr,&pppoe_header) == FALSE) {
					if (build_padt(&eth_hdr,&pppoe_header) == FALSE) {
						free(ppp_lcp_options);
						return ERROR;
					}
					goto out;
				}
			}
			cp = (ppp_payload.ppp_protocol == htons(IPCP_PROTOCOL)) ? 1 : 0;
			PPP_FSM(cp,&ppp_ports[cp],event,&eth_hdr,&pppoe_header,&ppp_payload,&ppp_lcp,ppp_lcp_options);
			break;
		case IPC_EV_TYPE_CLI:
			break;
		case IPC_EV_TYPE_MAP:
			break;
		default:
		    ;
		}
		
    }
out:
    free(ppp_lcp_options);
    return 0;
}
