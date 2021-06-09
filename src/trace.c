#include <rte_trace_point_register.h>

#include <rte_ethdev.h>
#include "trace.h"

RTE_TRACE_POINT_REGISTER(rte_ethdev_trace_rx_pkt, lib.ethdev.rx.pkt)