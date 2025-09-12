#include <grpc++/grpc++.h>
#include "vrg_grpc_cli.h"

#ifdef __cplusplus
extern "C" 
{
#endif

#include <rte_eal.h>
#include <rte_version.h>
#include <rte_ethdev.h>
#include "../../src/vrg.h"

#ifdef __cplusplus
}
#endif

using namespace std;
using namespace vrgcliservice;

extern struct rte_ring *rte_ring;

grpc::Status VRGCLIServiceImpl::ConnectHsi(::grpc::ServerContext* context, const ::vrgcliservice::HsiRequest* request, ::vrgcliservice::HsiReply* response)
{
    uint16_t user_id = request->user_id(), ccb_id = request->user_id() - 1;
    if (user_id > vrg_ccb->user_count) {
        std::string err = "Error! User " + std::to_string(user_id) + " is not exist";
        cout << err << endl;
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, err);
    }

    cout << "ConnectHsi called" << endl;
    if (user_id == 0) {
        for(int i=0; i<vrg_ccb->user_count; i++) {
            if (vrg_ccb->vrg_switch[i].is_hsi_enable == VRG_SUBMODULE_IS_ENABLED || 
                    vrg_ccb->vrg_switch[i].is_hsi_enable == VRG_SUBMODULE_IS_SPAWNED || 
                    vrg_ccb->vrg_switch[i].is_hsi_enable == VRG_SUBMODULE_IS_SPAWNING) {
                cout << "User " << i + 1 << " is already connected" << endl;
                continue;
            }
            vrg_ccb->vrg_switch[i].is_hsi_enable = VRG_SUBMODULE_IS_ENABLED;
        }
    } else {
        if (vrg_ccb->vrg_switch[ccb_id].is_hsi_enable == VRG_SUBMODULE_IS_ENABLED || 
                vrg_ccb->vrg_switch[ccb_id].is_hsi_enable == VRG_SUBMODULE_IS_SPAWNED || 
                vrg_ccb->vrg_switch[ccb_id].is_hsi_enable == VRG_SUBMODULE_IS_SPAWNING) {
            cout << "User " << user_id << " is already connected" << endl;
            return grpc::Status::OK;
        }
        vrg_ccb->vrg_switch[ccb_id].is_hsi_enable = VRG_SUBMODULE_IS_ENABLED;
    }

    return grpc::Status::OK;
}

grpc::Status VRGCLIServiceImpl::DisconnectHsi(::grpc::ServerContext* context, const ::vrgcliservice::HsiRequest* request, ::vrgcliservice::HsiReply* response)
{
    uint16_t user_id = request->user_id(), ccb_id = request->user_id() - 1;
    bool force = request->force();

    if (user_id > vrg_ccb->user_count) {
        std::string err = "Error! User " + std::to_string(user_id) + " is not exist";
        cout << err << endl;
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, err);
    }

    cout << "DisconnectHsi called" << endl;
    if (user_id == 0) {
        for(int i=0; i<vrg_ccb->user_count; i++) {
            if (force) {
                cout << "force disconnect" << i + 1 << endl;
                vrg_ccb->vrg_switch[i].is_hsi_enable = VRG_SUBMODULE_IS_FORCE_DISABLED;
                continue;
            }
            if (vrg_ccb->vrg_switch[i].is_hsi_enable == VRG_SUBMODULE_IS_DISABLED || 
                    vrg_ccb->vrg_switch[i].is_hsi_enable == VRG_SUBMODULE_IS_TERMINATED || 
                    vrg_ccb->vrg_switch[i].is_hsi_enable == VRG_SUBMODULE_IS_TERMINATING) {
                cout << "User " << i + 1 << " is already disconnected" << endl;
                continue;
            }
            vrg_ccb->vrg_switch[i].is_hsi_enable = VRG_SUBMODULE_IS_DISABLED;
        }
    } else {
        if (force) {
            cout << "force disconnect " << user_id << endl;
            vrg_ccb->vrg_switch[ccb_id].is_hsi_enable = VRG_SUBMODULE_IS_FORCE_DISABLED;
            return grpc::Status::OK;
        }
        if (vrg_ccb->vrg_switch[ccb_id].is_hsi_enable == VRG_SUBMODULE_IS_DISABLED || 
                vrg_ccb->vrg_switch[ccb_id].is_hsi_enable == VRG_SUBMODULE_IS_TERMINATED || 
                vrg_ccb->vrg_switch[ccb_id].is_hsi_enable == VRG_SUBMODULE_IS_TERMINATING) {
            cout << "User " << user_id << " is already disconnected" << endl;
            return grpc::Status::OK;
        }
        vrg_ccb->vrg_switch[ccb_id].is_hsi_enable = VRG_SUBMODULE_IS_DISABLED;
    }

    return grpc::Status::OK;
}

grpc::Status VRGCLIServiceImpl::DhcpServerStart(::grpc::ServerContext* context, const ::vrgcliservice::DhcpServerRequest* request, ::vrgcliservice::DhcpServerReply* response)
{
    uint16_t user_id = request->user_id(), ccb_id = request->user_id() - 1;

    if (user_id > vrg_ccb->user_count) {
        std::string err = "Error! User " + std::to_string(user_id) + " is not exist";
        cout << err << endl;
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, err);
    }

    cout << "DhcpServerStart called" << endl;
    if (user_id == 0) {
        std::string err;
        for(int i=0; i<vrg_ccb->user_count; i++) {
            if (vrg_ccb->vrg_switch[i].is_dhcp_server_enable == VRG_SUBMODULE_IS_ENABLED || 
                    vrg_ccb->vrg_switch[i].is_dhcp_server_enable == VRG_SUBMODULE_IS_SPAWNED || 
                    vrg_ccb->vrg_switch[i].is_dhcp_server_enable == VRG_SUBMODULE_IS_SPAWNING) {
                err += "User " + std::to_string(i + 1) + " dhcp server is already enabled\n";
                continue;
            }
            vrg_ccb->vrg_switch[i].is_dhcp_server_enable = VRG_SUBMODULE_IS_ENABLED;
        }
        if (!err.empty())
            return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, err);
    } else {
        if (vrg_ccb->vrg_switch[ccb_id].is_dhcp_server_enable == VRG_SUBMODULE_IS_ENABLED || 
                vrg_ccb->vrg_switch[ccb_id].is_dhcp_server_enable == VRG_SUBMODULE_IS_SPAWNED || 
                vrg_ccb->vrg_switch[ccb_id].is_dhcp_server_enable == VRG_SUBMODULE_IS_SPAWNING) {
            std::string err = "User " + std::to_string(user_id) + " dhcp server is already enabled";
            return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, err);
        }
        vrg_ccb->vrg_switch[ccb_id].is_dhcp_server_enable = VRG_SUBMODULE_IS_ENABLED;
    }

    return grpc::Status::OK;
}

grpc::Status VRGCLIServiceImpl::DhcpServerStop(::grpc::ServerContext* context, const ::vrgcliservice::DhcpServerRequest* request, ::vrgcliservice::DhcpServerReply* response)
{
    uint16_t user_id = request->user_id(), ccb_id = request->user_id() - 1;

    if (user_id > vrg_ccb->user_count) {
        std::string err = "Error! User " + std::to_string(user_id) + " is not exist";
        cout << err << endl;
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, err);
    }

    cout << "DhcpServerStop called" << endl;
    if (user_id == 0) {
        std::string err;
        for(int i=0; i<vrg_ccb->user_count; i++) {
            if (vrg_ccb->vrg_switch[i].is_dhcp_server_enable == VRG_SUBMODULE_IS_DISABLED || 
                    vrg_ccb->vrg_switch[i].is_dhcp_server_enable == VRG_SUBMODULE_IS_TERMINATED || 
                    vrg_ccb->vrg_switch[i].is_dhcp_server_enable == VRG_SUBMODULE_IS_TERMINATING) {
                err += "User " + std::to_string(i + 1) + " dhcp server is already disabled\n";
                continue;
            }
            vrg_ccb->vrg_switch[i].is_dhcp_server_enable = VRG_SUBMODULE_IS_DISABLED;
        }
        if (!err.empty())
            return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, err);
    } else {
        if (vrg_ccb->vrg_switch[ccb_id].is_dhcp_server_enable == VRG_SUBMODULE_IS_DISABLED || 
                vrg_ccb->vrg_switch[ccb_id].is_dhcp_server_enable == VRG_SUBMODULE_IS_TERMINATED || 
                vrg_ccb->vrg_switch[ccb_id].is_dhcp_server_enable == VRG_SUBMODULE_IS_TERMINATING) {
            std::string err = "User " + std::to_string(user_id) + " dhcp server is already disabled";
            return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, err);
        }
        vrg_ccb->vrg_switch[ccb_id].is_dhcp_server_enable = VRG_SUBMODULE_IS_DISABLED;
    }

    return grpc::Status::OK;
}

int getNicInfo(NicDriverInfo *nic_info, uint8_t port_id)
{
    struct rte_eth_dev_info dev_info = {0};
    if (rte_eth_dev_info_get(port_id, &dev_info) != 0) {
		std::string err = "get device info failed";
		return -1;
	}
    nic_info->set_driver_name(std::string(dev_info.driver_name));
    char buf[RTE_ETH_NAME_MAX_LEN];
    if (rte_eth_dev_get_name_by_port(port_id, buf) != 0) {
        std::string err = "get device pci addr failed";
        return -1;
    }
    nic_info->set_pci_addr(std::string(buf));

    return 0;
}

int getNicStats(Statistics *stats, uint8_t port_id)
{
    struct rte_eth_stats eth_stats = {0};
    if (rte_eth_stats_get(port_id, &eth_stats) != 0) {
        std::string err = "get device stats failed";
        return -1;
    }
    stats->set_rx_packets(eth_stats.ipackets);
    stats->set_tx_packets(eth_stats.opackets);
    stats->set_rx_bytes(eth_stats.ibytes);
    stats->set_tx_bytes(eth_stats.obytes);
    stats->set_rx_errors(eth_stats.ierrors);
    stats->set_tx_errors(eth_stats.oerrors);
    stats->set_rx_dropped(eth_stats.imissed);

    return 0;
}

grpc::Status VRGCLIServiceImpl::GetVrgSystemInfo(::grpc::ServerContext* context, const ::google::protobuf::Empty* request, ::vrgcliservice::VrgSystemInfo* response)
{
    uint8_t lan_port_id = 0, wan_port_id = 1;

    cout << "GetVrgSystemInfo called" << endl;
    VrgBaseInfo* base_info = response->mutable_base_info();
    base_info->set_vrg_version(std::string(vrg_ccb->version));
    base_info->set_build_date(std::string(vrg_ccb->build_date));
    base_info->set_dpdk_version(std::string(rte_version()));
    base_info->set_dpdk_eal_args(std::string(vrg_ccb->eal_args));
    base_info->set_num_users(vrg_ccb->user_count);

    NicDriverInfo *lan_nic_info = response->add_nics();
    if (getNicInfo(lan_nic_info, lan_port_id) != 0) {
        std::string err = "get lan device info failed";
        return grpc::Status(grpc::StatusCode::INTERNAL, err);
    }
    // mac addr
    lan_nic_info->set_mac_addr(std::string(
        reinterpret_cast<const char*>(vrg_ccb->nic_info.hsi_lan_mac.addr_bytes), 6));

    NicDriverInfo *wan_nic_info = response->add_nics();
    if (getNicInfo(wan_nic_info, wan_port_id) != 0) {
        std::string err = "get wan device info failed";
        return grpc::Status(grpc::StatusCode::INTERNAL, err);
    }
    // mac addr
    wan_nic_info->set_mac_addr(std::string(
        reinterpret_cast<const char*>(vrg_ccb->nic_info.hsi_wan_src_mac.addr_bytes), 6));

    Statistics *lan_stats = response->add_stats();
    if (getNicStats(lan_stats, lan_port_id) != 0) {
        std::string err = "get lan device stats failed";
        return grpc::Status(grpc::StatusCode::INTERNAL, err);
    }
    Statistics *wan_stats = response->add_stats();
    if (getNicStats(wan_stats, wan_port_id) != 0) {
        std::string err = "get wan device stats failed";
        return grpc::Status(grpc::StatusCode::INTERNAL, err);
    }

    return grpc::Status::OK;
}

grpc::Status VRGCLIServiceImpl:: GetVrgHsiInfo(::grpc::ServerContext* context, const ::google::protobuf::Empty* request, ::vrgcliservice::VrgHsiInfo* response) 
{
    cout << "GetVrgHsiInfo called" << endl;
    for(int i=0; i<vrg_ccb->user_count; i++) {
        HsiInfo* hsi_info = response->add_hsi_infos();
        hsi_info->set_user_id(i + 1);
        hsi_info->set_vlan_id(vrg_ccb->ppp_ccb[i].vlan);
        switch (vrg_ccb->ppp_ccb[i].phase) {
            case END_PHASE:
                hsi_info->set_status("init phase");
                break;
            case PPPOE_PHASE:
                hsi_info->set_status("pppoe phase");
                break;
            case LCP_PHASE:
                hsi_info->set_status("lcp phase");
                break;
            case AUTH_PHASE:
                hsi_info->set_status("auth phase");
                break;
            case IPCP_PHASE:
                hsi_info->set_status("ipcp phase");
                break;
            case DATA_PHASE:
                hsi_info->set_status("PPPoE connection");
                hsi_info->set_account(std::string(reinterpret_cast<const char*>(vrg_ccb->ppp_ccb->ppp_user_id)));
                hsi_info->set_password(std::string(reinterpret_cast<const char*>(vrg_ccb->ppp_ccb->ppp_passwd)));
                hsi_info->set_session_id(rte_be_to_cpu_16(vrg_ccb->ppp_ccb->session_id));
                hsi_info->set_ip_addr(std::to_string(*(((U8 *)&(vrg_ccb->ppp_ccb[i].hsi_ipv4)))) + "." +
                                     std::to_string(*(((U8 *)&(vrg_ccb->ppp_ccb[i].hsi_ipv4))+1)) + "." +
                                     std::to_string(*(((U8 *)&(vrg_ccb->ppp_ccb[i].hsi_ipv4))+2)) + "." +
                                     std::to_string(*(((U8 *)&(vrg_ccb->ppp_ccb[i].hsi_ipv4))+3)));
                hsi_info->set_gateway(std::to_string(*(((U8 *)&(vrg_ccb->ppp_ccb[i].hsi_ipv4_gw)))) + "." +
                                     std::to_string(*(((U8 *)&(vrg_ccb->ppp_ccb[i].hsi_ipv4_gw))+1)) + "." +
                                     std::to_string(*(((U8 *)&(vrg_ccb->ppp_ccb[i].hsi_ipv4_gw))+2)) + "." +
                                     std::to_string(*(((U8 *)&(vrg_ccb->ppp_ccb[i].hsi_ipv4_gw))+3)));
                hsi_info->add_dnss(std::to_string(*(((U8 *)&(vrg_ccb->ppp_ccb[i].hsi_primary_dns)))) + "." +
                                   std::to_string(*(((U8 *)&(vrg_ccb->ppp_ccb[i].hsi_primary_dns))+1)) + "." +
                                   std::to_string(*(((U8 *)&(vrg_ccb->ppp_ccb[i].hsi_primary_dns))+2)) + "." +
                                   std::to_string(*(((U8 *)&(vrg_ccb->ppp_ccb[i].hsi_primary_dns))+3)));
                hsi_info->add_dnss(std::to_string(*(((U8 *)&(vrg_ccb->ppp_ccb[i].hsi_second_dns)))) + "." +
                                   std::to_string(*(((U8 *)&(vrg_ccb->ppp_ccb[i].hsi_second_dns))+1)) + "." +
                                   std::to_string(*(((U8 *)&(vrg_ccb->ppp_ccb[i].hsi_second_dns))+2)) + "." +
                                   std::to_string(*(((U8 *)&(vrg_ccb->ppp_ccb[i].hsi_second_dns))+3)));
                break;
            default:
                hsi_info->set_status("unknown status");
                break;
        }
    }

    return grpc::Status::OK;
}

grpc::Status VRGCLIServiceImpl:: GetVrgDhcpInfo(::grpc::ServerContext* context, const ::google::protobuf::Empty* request, ::vrgcliservice::VrgDhcpInfo* response) 
{
    cout << "GetVrgDhcpInfo called" << endl;
    dhcp_ccb_t *dhcp_ccb = vrg_ccb->dhcp_ccb;
    for(int i=0; i<vrg_ccb->user_count; i++) {
        DhcpInfo* dhcp_info = response->add_dhcp_infos();
        if (rte_atomic16_read(&vrg_ccb->dhcp_ccb[i].dhcp_bool) == 1) {
            dhcp_info->set_user_id(i + 1);
            dhcp_info->set_status("DHCP server is on");

			for(U8 j=0; j<MAX_IP_POOL; j++) {
				if (dhcp_ccb[i].ip_pool[j].used) {
                    dhcp_info->add_inuse_ips(std::to_string(*(((U8 *)&(dhcp_ccb[i].ip_pool[j].ip_addr)))) + "." +
                        std::to_string(*(((U8 *)&(dhcp_ccb[i].ip_pool[j].ip_addr))+1)) + "." +
                        std::to_string(*(((U8 *)&(dhcp_ccb[i].ip_pool[j].ip_addr))+2)) + "." +
                        std::to_string(*(((U8 *)&(dhcp_ccb[i].ip_pool[j].ip_addr))+3)));
				}
			}
		}
		else {
            dhcp_info->set_user_id(i + 1);
            dhcp_info->set_status("DHCP server is off");
        }

        dhcp_info->set_start_ip(std::to_string(*(((U8 *)&(dhcp_ccb[i].ip_pool[0].ip_addr)))) + "." +
            std::to_string(*(((U8 *)&(dhcp_ccb[i].ip_pool[0].ip_addr))+1)) + "." +
            std::to_string(*(((U8 *)&(dhcp_ccb[i].ip_pool[0].ip_addr))+2)) + "." +
            std::to_string(*(((U8 *)&(dhcp_ccb[i].ip_pool[0].ip_addr))+3)));
        dhcp_info->set_end_ip(std::to_string(*(((U8 *)&(dhcp_ccb[i].ip_pool[MAX_IP_POOL - 1].ip_addr)))) + "." +
            std::to_string(*(((U8 *)&(dhcp_ccb[i].ip_pool[MAX_IP_POOL - 1].ip_addr))+1)) + "." +
            std::to_string(*(((U8 *)&(dhcp_ccb[i].ip_pool[MAX_IP_POOL - 1].ip_addr))+2)) + "." +
            std::to_string(*(((U8 *)&(dhcp_ccb[i].ip_pool[MAX_IP_POOL - 1].ip_addr))+3)));
        dhcp_info->set_subnet_mask("255.255.255.0");
        dhcp_info->set_gateway(std::to_string(*(((U8 *)&(dhcp_ccb[i].dhcp_server_ip)))) + "." +
            std::to_string(*(((U8 *)&(dhcp_ccb[i].dhcp_server_ip))+1)) + "." +
            std::to_string(*(((U8 *)&(dhcp_ccb[i].dhcp_server_ip))+2)) + "." +
            std::to_string(*(((U8 *)&(dhcp_ccb[i].dhcp_server_ip))+3)));
    }
    return grpc::Status::OK;
}
