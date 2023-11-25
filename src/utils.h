#ifndef _UTILS_H_
#define _UTILS_H_

#include <rte_malloc.h>
#include <rte_ring.h>
#include <common.h>
#include "protocol.h"

#define RING_BURST_SIZE 32

/**
 * @brief msg between IF driver and daemon
 */
typedef struct {
	U16  			type;
	U8          	refp[ETH_JUMBO];
	int	        	len;
} tVRG_MBX;

/* only execution when condition is true */
#define VRG_ASSERT(cond, op, ret) do { \
    if (unlikely(!(cond))) { \
        (ret) = (op); \
    } \
} while(0)

static inline void *_vrg_malloc(size_t size, unsigned int aligned) {
    if (unlikely(size == 0)) {
        return NULL;
    }
    return rte_malloc(NULL, size, aligned);
}

static inline void vrg_mfree(void *ptr) {
    if (unlikely(ptr == NULL)) {
        return;
    }
    rte_free(ptr);
}

#define vrg_malloc(type, size, aligned) (type *)_vrg_malloc(size, aligned)

/**
 * vrg_ring_enqueue
 * 
 * @brief 
 *      vrg lockless ring enqueue, it will try to enqueue all mails
 * @param ring
 *      ring pointer
 * @param mails
 *      mail array
 * @param enqueue_num
 *      mail amount
 * @return
 *      void
 */ 
static inline void vrg_ring_enqueue(struct rte_ring *ring, void **mails, unsigned int enqueue_num)
{
	unsigned int burst_size = 0;
    unsigned int rest_num = enqueue_num;

	for(;;) {
        int rest_mails_index = enqueue_num - rest_num;
        burst_size = rte_ring_enqueue_burst(ring, &mails[rest_mails_index], rest_num, NULL);
        rest_num -= burst_size;
        if (likely(rest_num == 0))
            break;
	}
	return;
}

/**
 * vrg_ring_dequeue
 * 
 * @brief 
 *      vrg lockless ring dequeue, it will return once there is a mail
 * @param ring
 *      ring pointer
 * @param mails
 *      mail array
 * @return
 *      mail amount
 */ 
static inline int vrg_ring_dequeue(struct rte_ring *ring, void **mail)
{
	U16 burst_size;

	for(;;) {
		burst_size = rte_ring_dequeue_burst(ring, mail, RING_BURST_SIZE, NULL);
		if (likely(burst_size == 0))
			continue;
		break;
	}
	return burst_size;
}

struct lcore_map {
	U8 ctrl_thread;
	U8 wan_thread;
	U8 down_thread;
	U8 lan_thread;
	U8 up_thread;
	U8 gateway_thread;
	U8 timer_thread;
    U8 northbound_thread;
};

void get_all_lcore_id(struct lcore_map *lcore);

#endif