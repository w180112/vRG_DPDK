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

extern struct rte_mempool *direct_pool;
extern struct rte_mempool *indirect_pool;
extern struct rte_ring     *rte_ring, /**decap_udp, *decap_tcp, *encap_udp, *encap_tcp,*/ /**ds_mc_queue, *us_mc_queue,*/ *rg_func_queue;
//extern struct rte_mempool  *mbuf_pool;

#endif