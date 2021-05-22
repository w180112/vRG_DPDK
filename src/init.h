/*\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\
   init.h
  
     Initiation of vRG

  Designed by THE on Jan 26, 2021
/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\*/
#include 	"codec.h"
#include 	<common.h>
#include 	<cmdline.h>

#ifndef _INIT_H_
#define _INIT_H_

#define PORT_AMOUNT       2

extern int sys_init(struct cmdline *cl);

extern struct rte_mempool *direct_pool[PORT_AMOUNT];
extern struct rte_mempool *indirect_pool[PORT_AMOUNT];
extern struct rte_ring     *rte_ring, *gateway_q, *uplink_q, *downlink_q;
//extern struct rte_mempool  *mbuf_pool;

typedef struct nic_vendor {
    const char 		*vendor;
    U8				vendor_id;
}nic_vendor_t;

#endif