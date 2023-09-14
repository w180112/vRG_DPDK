#include <common.h>
#include <libconfig.h>
#include "vrg.h"
#include "dbg.h"

STATUS parse_config(const char *config_path, VRG_t *vrg_ccb) 
{
    config_t cfg;
    int user_count, base_vlan;

    config_init(&cfg);
    if(!config_read_file(&cfg, config_path)) {
        VRG_LOG(INFO, NULL, NULL, NULL, "read config file %s content error: %s:%d - %s", 
                config_path, config_error_file(&cfg), config_error_line(&cfg), config_error_text(&cfg));
        config_destroy(&cfg);
        return ERROR;
    }
    if(config_lookup_int(&cfg, "UserCount", &user_count) == CONFIG_FALSE)
        user_count = 1;
    vrg_ccb->user_count = user_count;
    if(config_lookup_int(&cfg, "BaseVlan", &base_vlan) == CONFIG_FALSE)
        base_vlan = 2;
    vrg_ccb->base_vlan = base_vlan;
    
    config_destroy(&cfg);

    return SUCCESS;
}