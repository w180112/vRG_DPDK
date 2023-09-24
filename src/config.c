#include <common.h>
#include <libconfig.h>
#include "vrg.h"
#include "dbg.h"

STATUS parse_config(const char *config_path, VRG_t *vrg_ccb) 
{
    config_t cfg;
    int user_count, base_vlan, non_vlan_mode;
    const char *loglvl, *default_gateway;

    config_init(&cfg);
    if (!config_read_file(&cfg, config_path)) {
        VRG_LOG(INFO, NULL, NULL, NULL, "read config file %s content error: %s:%d - %s", 
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
        VRG_LOG(INFO, NULL, NULL, NULL, "log level error");
        config_destroy(&cfg);
        return ERROR;
    }
    if (config_lookup_int(&cfg, "NonVlanMode", &non_vlan_mode) == CONFIG_FALSE)
        non_vlan_mode = 0;
    vrg_ccb->non_vlan_mode = non_vlan_mode;

    if (config_lookup_string(&cfg, "DefaultGateway", &default_gateway) == CONFIG_FALSE)
        default_gateway = "192.168.2.1";
    vrg_ccb->lan_ip = rte_cpu_to_be_32(inet_addr(default_gateway));
    
    config_destroy(&cfg);

    return SUCCESS;
}