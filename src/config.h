/*\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\
  CONFIG.H

  Designed by THE on Sep 15, 2023
/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\*/

#ifndef _CONFIG_H_
#define _CONFIG_H_

#include "vrg.h"

struct vrg_config {
    char unix_sock_path[256];
    char node_grpc_ip_port[256];
    char log_path[256];
};

STATUS parse_config(const char *config_path, VRG_t *vrg_ccb, struct vrg_config *vrg_cfg);

#endif
