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
        for(int i=0; i<vrg_ccb->user_count; i++) {
            if (vrg_ccb->vrg_switch[i].is_dhcp_server_enable == VRG_SUBMODULE_IS_ENABLED || 
                    vrg_ccb->vrg_switch[i].is_dhcp_server_enable == VRG_SUBMODULE_IS_SPAWNED || 
                    vrg_ccb->vrg_switch[i].is_dhcp_server_enable == VRG_SUBMODULE_IS_SPAWNING) {
                cout << "User " << i + 1 << " dhcp server is already enabled" << endl;
                continue;
            }
            vrg_ccb->vrg_switch[i].is_dhcp_server_enable = VRG_SUBMODULE_IS_ENABLED;
        }
    } else {
        if (vrg_ccb->vrg_switch[ccb_id].is_dhcp_server_enable == VRG_SUBMODULE_IS_ENABLED || 
                vrg_ccb->vrg_switch[ccb_id].is_dhcp_server_enable == VRG_SUBMODULE_IS_SPAWNED || 
                vrg_ccb->vrg_switch[ccb_id].is_dhcp_server_enable == VRG_SUBMODULE_IS_SPAWNING) {
            cout << "User " << user_id << " dhcp server is already enabled" << endl;
            return grpc::Status::OK;
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
        for(int i=0; i<vrg_ccb->user_count; i++) {
            if (vrg_ccb->vrg_switch[i].is_dhcp_server_enable == VRG_SUBMODULE_IS_DISABLED || 
                    vrg_ccb->vrg_switch[i].is_dhcp_server_enable == VRG_SUBMODULE_IS_TERMINATED || 
                    vrg_ccb->vrg_switch[i].is_dhcp_server_enable == VRG_SUBMODULE_IS_TERMINATING) {
                cout << "User " << i + 1 << " dhcp server is already disabled" << endl;
                continue;
            }
            vrg_ccb->vrg_switch[i].is_dhcp_server_enable = VRG_SUBMODULE_IS_DISABLED;
        }
    } else {
        if (vrg_ccb->vrg_switch[ccb_id].is_dhcp_server_enable == VRG_SUBMODULE_IS_DISABLED || 
                vrg_ccb->vrg_switch[ccb_id].is_dhcp_server_enable == VRG_SUBMODULE_IS_TERMINATED || 
                vrg_ccb->vrg_switch[ccb_id].is_dhcp_server_enable == VRG_SUBMODULE_IS_TERMINATING) {
            cout << "User " << user_id << " dhcp server is already disabled" << endl;
            return grpc::Status::OK;
        }
        vrg_ccb->vrg_switch[ccb_id].is_dhcp_server_enable = VRG_SUBMODULE_IS_DISABLED;
    }

    return grpc::Status::OK;
}

int getNicInfo(NicDriverInfo *nic_info, uint8_t port_id) {
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

    return grpc::Status::OK;
}
