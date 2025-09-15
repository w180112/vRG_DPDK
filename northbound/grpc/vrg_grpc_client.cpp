#include <iostream>
#include <grpc++/grpc++.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>
#include "vrg_node_grpc.h"
#include "../../src/vrg.h"

#ifdef __cplusplus
extern "C" {
#endif

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using vrgnodeservice::VrgService;
using vrgnodeservice::HsiRequest;
using vrgnodeservice::HsiReply;

class VRGNodeClient {
    public:
        VRGNodeClient(std::shared_ptr<Channel> channel):stub_(VrgService::NewStub(channel)) {}
    std::unique_ptr<VrgService::Stub> stub_;
};

std::unique_ptr<VRGNodeClient> vrg_client;

void vrg_grpc_client_connect(char *server_address) {
    std::cout << "grpc client connecting to " << server_address << std::endl;
    auto channel = grpc::CreateChannel(server_address, grpc::InsecureChannelCredentials());
    vrg_client = std::make_unique<VRGNodeClient>(channel);
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
    std::cout << "grpc client getting vRG system and node info" << std::endl;
    google::protobuf::Empty request;
    VrgSystemInfo reply_vrg_system;
    NodeStatus reply_node_status;
    ClientContext context_vrg_system, context_node_status;
    Status status = vrg_client->stub_->GetVrgSystemInfo(&context_vrg_system, request, &reply_vrg_system);
    if (status.ok()) {
        std::cout << "grpc client get vRG system info ok" << std::endl;
        std::cout << "  vRG version: " << reply_vrg_system.base_info().vrg_version() << std::endl;
        std::cout << "  Build date: " << reply_vrg_system.base_info().build_date() << std::endl;
        std::cout << "  DPDK version: " << reply_vrg_system.base_info().dpdk_version() << std::endl;
        std::cout << "  DPDK EAL args: " << reply_vrg_system.base_info().dpdk_eal_args() << std::endl;
        std::cout << "  Number of subscribers: " << reply_vrg_system.base_info().num_users() << std::endl;

        std::cout << "  NICs: " << std::endl;
        for(int i=0; i<reply_vrg_system.nics_size() && i<reply_vrg_system.stats_size(); i++) {
            const NicDriverInfo& nic_info = reply_vrg_system.nics(i);
            std::cout << "    NIC " << i << ":" << std::endl;
            std::cout << "      Driver name: " << nic_info.driver_name() << std::endl;
            std::cout << "      PCI address: " << nic_info.pci_addr() << std::endl;
            std::cout << "      MAC address: ";
            std::string mac_bin = nic_info.mac_addr();
            const uint8_t* mac_bytes = reinterpret_cast<const uint8_t*>(mac_bin.data());
            for(size_t j=0; j<mac_bin.size(); j++)
                printf("%02x%c", mac_bytes[j], (j == mac_bin.size()-1 ? '\n' : ':'));
            const Statistics& stats = reply_vrg_system.stats(i);
            std::cout << "      Rx packets: " << stats.rx_packets() << std::endl;
            std::cout << "      Tx packets: " << stats.tx_packets() << std::endl;
            std::cout << "      Rx bytes: " << stats.rx_bytes() << std::endl;
            std::cout << "      Tx bytes: " << stats.tx_bytes() << std::endl;
            std::cout << "      Rx errors: " << stats.rx_errors() << std::endl;
            std::cout << "      Tx errors: " << stats.tx_errors() << std::endl;
            std::cout << "      Rx dropped: " << stats.rx_dropped() << std::endl;
        }
    } else {
        std::cout << "grpc client get info failed: " << std::endl;
        std::cout << "  Error code: " << status.error_code() << std::endl;
        std::cout << "  Error message: " << status.error_message() << std::endl;
    }

    context_node_status.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(5));
    status = vrg_client->stub_->GetNodeStatus(&context_node_status, request, &reply_node_status);
    if (status.ok()) {
        std::cout << "grpc client get node status ok" << std::endl;
        std::cout << "  Node OS version: " << reply_node_status.node_os_version() << std::endl;
        std::cout << "  Node uptime (seconds): " << reply_node_status.node_uptime() << std::endl;
        std::cout << "  Node IP address: " << reply_node_status.node_ip_info() << std::endl;
        std::cout << "  Health status: " << (reply_node_status.healthy() ? "Healthy" : "Unhealthy") << std::endl;

    } else {
        std::cout << "grpc client get node status failed: " << std::endl;
        std::cout << "  Error code: " << status.error_code() << std::endl;
        std::cout << "  Error message: " << status.error_message() << std::endl;
    }
}

void vrg_grpc_get_hsi_info() {
    std::cout << "grpc client getting hsi info" << std::endl;
    google::protobuf::Empty request;
    VrgHsiInfo reply;
    ClientContext context;
    Status status = vrg_client->stub_->GetVrgHsiInfo(&context, request, &reply);
    if (status.ok()) {
        std::cout << "grpc client get hsi info ok" << std::endl;
        for(int i=0; i<reply.hsi_infos_size(); i++) {
            const HsiInfo& hsi_info = reply.hsi_infos(i);
            std::cout << "  HSI " << i << ":" << std::endl;
            std::cout << "    User ID: " << hsi_info.user_id() << std::endl;
            std::cout << "    VLAN ID: " << hsi_info.vlan_id() << std::endl;
            std::cout << "    Status: " << hsi_info.status() << std::endl;
            std::cout << "    Account: " << hsi_info.account() << std::endl;
            std::cout << "    Password: " << hsi_info.password() << std::endl;
            std::cout << "    Session ID: " << hsi_info.session_id() << std::endl;
            std::cout << "    IP address: " << hsi_info.ip_addr() << std::endl;
            std::cout << "    Gateway: " << hsi_info.gateway() << std::endl;
            std::cout << "    DNS servers: ";
            for(int j=0; j<hsi_info.dnss_size(); j++) {
                std::cout << hsi_info.dnss(j);
                if (j < hsi_info.dnss_size() - 1)
                    std::cout << ", ";
            }
            std::cout << std::endl;
        }
    } else {
        std::cout << "grpc client get hsi info failed: " << std::endl;
        std::cout << "  Error code: " << status.error_code() << std::endl;
        std::cout << "  Error message: " << status.error_message() << std::endl;
    }
}

void vrg_grpc_get_dhcp_info() {
    std::cout << "grpc client getting dhcp info" << std::endl;
    google::protobuf::Empty request;
    VrgDhcpInfo reply;
    ClientContext context;
    Status status = vrg_client->stub_->GetVrgDhcpInfo(&context, request, &reply);
    if (status.ok()) {
        std::cout << "grpc client get dhcp info ok" << std::endl;
        for(int i=0; i<reply.dhcp_infos_size(); i++) {
            const DhcpInfo& dhcp_info = reply.dhcp_infos(i);
            std::cout << "  DHCP " << i << ":" << std::endl;
            std::cout << "    User ID: " << dhcp_info.user_id() << std::endl;
            std::cout << "    Status: " << dhcp_info.status() << std::endl;
            std::cout << "    Start IP: " << dhcp_info.start_ip() << std::endl;
            std::cout << "    End IP: " << dhcp_info.end_ip() << std::endl;
            std::cout << "    Subnet Mask: " << dhcp_info.subnet_mask() << std::endl;
            std::cout << "    Gateway: " << dhcp_info.gateway() << std::endl;
            std::cout << "    In-use IPs: ";
            for(int j=0; j<dhcp_info.inuse_ips_size(); j++) {
                std::cout << dhcp_info.inuse_ips(j);
                if (j < dhcp_info.inuse_ips_size() - 1)
                    std::cout << ", ";
            }
            std::cout << std::endl;
            std::cout << "    DNS servers: ";
            for(int j=0; j<dhcp_info.dnss_size(); j++) {
                std::cout << dhcp_info.dnss(j);
                if (j < dhcp_info.dnss_size() - 1)
                    std::cout << ", ";
            }
            std::cout << std::endl;
        }
    } else {
        std::cout << "grpc client get dhcp info failed: " << std::endl;
        std::cout << "  Error code: " << status.error_code() << std::endl;
        std::cout << "  Error message: " << status.error_message() << std::endl;
    }
}

#ifdef __cplusplus
}
#endif
