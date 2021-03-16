/*\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\
 	init.h
  
     Initiation of vRG

  Designed by THE on Jan 26, 2021
/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\*/
#include 	"codec.h"
#include 	<common.h>

#ifndef _INIT_H_
#define _INIT_H_

#define PORT_AMOUNT       2

extern int sys_init(void);

extern struct rte_mempool *direct_pool[PORT_AMOUNT];
extern struct rte_mempool *indirect_pool[PORT_AMOUNT];
extern struct rte_ring     *rte_ring, *rg_func_q, *uplink_q, *downlink_q;
//extern struct rte_mempool  *mbuf_pool;

#endif