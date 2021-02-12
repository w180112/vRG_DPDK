#include <rte_flow.h>

extern struct rte_flow *generate_flow(uint16_t port_id, uint16_t rx_q, struct rte_flow_error *error);