#ifndef _PROTOCOL_H_
#define _PROTOCOL_H_

#include <common.h>

#define ETH_MTU				1500

#define ETH_P_PPP_DIS 		0x8863
#define ETH_P_PPP_SES		0x8864
#define VLAN                0x8100

/**
 * @brief We use bit feild here, but bit field order is uncertain.
 * It depends on compiler implementation.
 * In GCC, bit field is bind with endianess.
 * https://rednaxelafx.iteye.com/blog/257760
 * http://www.programmer-club.com.tw/ShowSameTitleN/general/6887.html
 * http://pl-learning-blog.logdown.com/posts/1077056-usually-terror-words-o-muhammad-c-ch13-reading-notes-unfinished
 */
typedef struct vlan_header {
	union tci_header {
		U16 tci_value;
		struct tci_bit {
			#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
			U16 vlan_id:12;
			U16 DEI:1;
			U16 priority:3;
			#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
			U16 priority:3;
			U16 DEI:1;
			U16 vlan_id:12;
			#endif
		}tci_struct;
	}tci_union;
	U16 next_proto;
}__rte_aligned(2) vlan_header_t;

#endif