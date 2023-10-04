/*\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\
   init.h
  
     Initiation of vRG

  Designed by THE on Jan 26, 2021
/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\*/
#include <common.h>
#include <cmdline.h>
#include "vrg.h"
#include "pppd/codec.h"

#ifndef _INIT_H_
#define _INIT_H_

#define PORT_AMOUNT       2

#define MLX5					1
#define IXGBE					2
#define I40E					3
#define VMXNET3					4
#define IXGBEVF					5
#define I40EVF					6

extern int sys_init(VRG_t *vrg_ccb);

extern struct rte_mempool *direct_pool[PORT_AMOUNT];
extern struct rte_mempool *indirect_pool[PORT_AMOUNT];
extern struct rte_ring     *rte_ring, *gateway_q, *uplink_q, *downlink_q;
//extern struct rte_mempool  *mbuf_pool;

#endif