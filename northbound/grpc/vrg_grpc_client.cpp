#include <iostream>
#include <grpc++/grpc++.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>
#include "vrg_grpc_cli.h"
#include "../../src/vrg.h"

#ifdef __cplusplus
extern "C" {
#endif

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using vrgcliservice::VrgService;
using vrgcliservice::HsiRequest;
using vrgcliservice::HsiReply;

class VRGCliClient {
    public:
        VRGCliClient(std::shared_ptr<Channel> channel):stub_(VrgService::NewStub(channel)) {}
    std::unique_ptr<VrgService::Stub> stub_;
};

std::unique_ptr<VRGCliClient> vrg_client;

void vrg_grpc_client_connect(char *server_address) {
    std::cout << "grpc client connecting to " << server_address << std::endl;
    auto channel = grpc::CreateChannel(server_address, grpc::InsecureChannelCredentials());
    vrg_client = std::make_unique<VRGCliClient>(channel);
    std::cout << "grpc client connected to " << server_address << std::endl;

    return;
}

void vrg_grpc_hsi_connect(U8 user_id) {
    std::cout << "grpc client hsi connect" << std::endl;
    HsiRequest request;
    HsiReply reply;
    request.set_user_id(user_id);
    ClientContext context;
    Status status = vrg_client->stub_->ConnectHsi(&context, request, &reply);
    if (status.ok()) {
        std::cout << "grpc client hsi connect ok" << std::endl;
    } else {
        std::cout << "grpc client hsi connect failed: " << std::endl;
        std::cout << "  Error code: " << status.error_code() << std::endl;
        std::cout << "  Error message: " << status.error_message() << std::endl;
    }
    return;
}

void vrg_grpc_hsi_disconnect(U8 user_id, bool force) {
    std::cout << "grpc client hsi disconnect" << std::endl;
    HsiRequest request;
    HsiReply reply;
    request.set_user_id(user_id);
    request.set_force(force);
    ClientContext context;
    Status status = vrg_client->stub_->DisconnectHsi(&context, request, &reply);
    if (status.ok()) {
        std::cout << "grpc client hsi disconnect ok" << std::endl;
    } else {
        std::cout << "grpc client hsi disconnect failed: " << std::endl;
        std::cout << "  Error code: " << status.error_code() << std::endl;
        std::cout << "  Error message: " << status.error_message() << std::endl;
    }
    return;
}

void vrg_grpc_dhcp_server_start(U8 user_id) {
    std::cout << "grpc client dhcp server start" << std::endl;
    DhcpServerRequest request;
    DhcpServerReply reply;
    request.set_user_id(user_id);
    ClientContext context;
    Status status = vrg_client->stub_->DhcpServerStart(&context, request, &reply);
    if (status.ok()) {
        std::cout << "grpc client dhcp server start ok" << std::endl;
    } else {
        std::cout << "grpc client dhcp server start failed: " << std::endl;
        std::cout << "  Error code: " << status.error_code() << std::endl;
        std::cout << "  Error message: " << status.error_message() << std::endl;
    }
    return;
}

void vrg_grpc_dhcp_server_stop(U8 user_id) {
    std::cout << "grpc client dhcp server stop" << std::endl;
    DhcpServerRequest request;
    DhcpServerReply reply;
    request.set_user_id(user_id);
    ClientContext context;
    Status status = vrg_client->stub_->DhcpServerStop(&context, request, &reply);
    if (status.ok()) {
        std::cout << "grpc client dhcp server stop ok" << std::endl;
    } else {
        std::cout << "grpc client dhcp server stop failed: " << std::endl;
        std::cout << "  Error code: " << status.error_code() << std::endl;
        std::cout << "  Error message: " << status.error_message() << std::endl;
    }
    return;
}

void vrg_grpc_get_system_info() {
    std::cout << "grpc client getting system info" << std::endl;
    google::protobuf::Empty request;
    VrgSystemInfo reply;
    ClientContext context;
    Status status = vrg_client->stub_->GetVrgSystemInfo(&context, request, &reply);
    if (status.ok()) {
        std::cout << "grpc client get system info ok" << std::endl;
        std::cout << "  vRG version: " << reply.base_info().vrg_version() << std::endl;
        std::cout << "  Build date: " << reply.base_info().build_date() << std::endl;
        std::cout << "  DPDK version: " << reply.base_info().dpdk_version() << std::endl;
        std::cout << "  DPDK EAL args: " << reply.base_info().dpdk_eal_args() << std::endl;
        std::cout << "  Number of subscribers: " << reply.base_info().num_users() << std::endl;

        std::cout << "  NICs: " << std::endl;
        for(int i=0; i<reply.nics_size(); i++) {
            const NicDriverInfo& nic_info = reply.nics(i);
            std::cout << "    NIC " << i << ":" << std::endl;
            std::cout << "      Driver name: " << nic_info.driver_name() << std::endl;
            std::cout << "      PCI address: " << nic_info.pci_addr() << std::endl;
            std::cout << "      MAC address: ";
            std::string mac_bin = nic_info.mac_addr();
            const uint8_t* mac_bytes = reinterpret_cast<const uint8_t*>(mac_bin.data());
            for(size_t j=0; j<mac_bin.size(); j++)
                printf("%02x%c", mac_bytes[j], (j == mac_bin.size()-1 ? '\n' : ':'));
        }
    } else {
        std::cout << "grpc client get info failed: " << std::endl;
        std::cout << "  Error code: " << status.error_code() << std::endl;
        std::cout << "  Error message: " << status.error_message() << std::endl;
    }
}

void vrg_grpc_get_hsi_info() {
}

void vrg_grpc_get_dhcp_info() {
}

#ifdef __cplusplus
}
#endif
