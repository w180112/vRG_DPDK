/*\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\
  TRACE.H

  Designed by THE on JUN 11, 2019
/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\*/

#ifndef _TRACE_H_
#define _TRACE_H_

#include <rte_trace_point.h>
#include <common.h>

RTE_TRACE_POINT_FP(
       rte_ethdev_trace_rx_pkt,
       RTE_TRACE_POINT_ARGS(U8 *payload),
       rte_trace_point_emit_ptr(payload);
)

#endif