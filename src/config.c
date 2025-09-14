#include <common.h>
#include <libconfig.h>
#include "vrg.h"
#include "dbg.h"
#include "config.h"

STATUS parse_config(const char *config_path, VRG_t *vrg_ccb, struct vrg_config *vrg_cfg) 
{
    config_t cfg;
    int user_count, base_vlan, non_vlan_mode;
    const char *loglvl, *default_gateway, *unix_sock_path, *log_path, *node_grpc_port;

    config_init(&cfg);
    if (!config_read_file(&cfg, config_path)) {
        fprintf(stderr, "read config file %s content error: %s:%d - %s\n", 
                config_path, config_error_file(&cfg), config_error_line(&cfg), config_error_text(&cfg));
        config_destroy(&cfg);
        return ERROR;
    }
    if (config_lookup_int(&cfg, "UserCount", &user_count) == CONFIG_FALSE)
        user_count = 1;
    vrg_ccb->user_count = user_count;
    if (config_lookup_int(&cfg, "BaseVlan", &base_vlan) == CONFIG_FALSE)
        base_vlan = 2;
    vrg_ccb->base_vlan = base_vlan;
    if (config_lookup_string(&cfg, "Loglvl", &loglvl) == CONFIG_FALSE)
        loglvl = "DBG";
    vrg_ccb->loglvl = logstr2lvl(loglvl);
    if (vrg_ccb->loglvl == 0) {
        fprintf(stderr, "log level error\n");
        config_destroy(&cfg);
        return ERROR;
    }
    if (config_lookup_string(&cfg, "LogPath", &log_path) == CONFIG_FALSE) {
        log_path = "/var/log/vrg/vrg.log";
        printf("log path not found, use default path: %s\n", log_path);
    }
    strncpy(vrg_cfg->log_path, log_path, sizeof(vrg_cfg->log_path) - 1);
    vrg_cfg->log_path[sizeof(vrg_cfg->log_path) - 1] = '\0';

    if (config_lookup_int(&cfg, "NonVlanMode", &non_vlan_mode) == CONFIG_FALSE)
        non_vlan_mode = 0;
    vrg_ccb->non_vlan_mode = non_vlan_mode;

    if (config_lookup_string(&cfg, "DefaultGateway", &default_gateway) == CONFIG_FALSE)
        default_gateway = "192.168.2.1";
    vrg_ccb->lan_ip = inet_addr(default_gateway);

    if (config_lookup_string(&cfg, "NodeGrpcUnixSocket", &unix_sock_path) == CONFIG_FALSE)
        unix_sock_path = "unix:///var/run/vrg/vrg.sock";
    strncpy(vrg_cfg->unix_sock_path, unix_sock_path, sizeof(vrg_cfg->unix_sock_path) - 1);
    vrg_cfg->unix_sock_path[sizeof(vrg_cfg->unix_sock_path) - 1] = '\0';

    if (config_lookup_string(&cfg, "NodeGrpcPort", &node_grpc_port) == CONFIG_FALSE)
        node_grpc_port = "50051";    
    char node_grpc_ip_port[64];  // 足夠放 "0.0.0.0:PORT"
    snprintf(node_grpc_ip_port, sizeof(node_grpc_ip_port), "0.0.0.0:%s", node_grpc_port);
    strncpy(vrg_cfg->node_grpc_ip_port, node_grpc_ip_port, sizeof(vrg_cfg->node_grpc_ip_port) - 1);
    vrg_cfg->node_grpc_ip_port[sizeof(vrg_cfg->node_grpc_ip_port) - 1] = '\0';

    config_destroy(&cfg);

    return SUCCESS;
}