#include <grpc++/grpc++.h>
#include "vrg_grpc_cli.h"

#ifdef __cplusplus
extern "C" 
{
#endif

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
