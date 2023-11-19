#ifndef _UTILS_H_
#define _UTILS_H_

#include <rte_malloc.h>
#include <common.h>
#include "dbg.h"

/* only execution when condition is true */
#define VRG_ASSERT(cond, op, ret) do { \
    if (unlikely(!(cond))) { \
        (ret) = (op); \
    } \
} while(0)

static inline void *_vrg_malloc(size_t size, unsigned int aligned) {
    if (unlikely(size == 0)) {
        VRG_LOG(ERR, NULL, NULL, NULL, "malloc size is 0");
        return NULL;
    }
    return rte_malloc(NULL, size, aligned);
}

static inline void vrg_mfree(void *ptr) {
    if (unlikely(ptr == NULL)) {
        VRG_LOG(ERR, NULL, NULL, NULL, "free ptr is NULL");
        return;
    }
    rte_free(ptr);
}

#define vrg_malloc(type, size, aligned) (type *)_vrg_malloc(size, aligned)

struct lcore_map {
	U8 ctrl_thread;
	U8 wan_thread;
	U8 down_thread;
	U8 lan_thread;
	U8 up_thread;
	U8 gateway_thread;
	U8 timer_thread;
};

void get_all_lcore_id(struct lcore_map *lcore);
int control_plane_dequeue(void **mail);

#endif