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
        std::cout << "grpc client hsi connect failed" << std::endl;
    }
    return;
}

void vrg_grpc_hsi_disconnect(U8 user_id) {
    std::cout << "grpc client hsi disconnect" << std::endl;
    HsiRequest request;
    HsiReply reply;
    request.set_user_id(user_id);
    ClientContext context;
    Status status = vrg_client->stub_->DisconnectHsi(&context, request, &reply);
    if (status.ok()) {
        std::cout << "grpc client hsi disconnect ok" << std::endl;
    } else {
        std::cout << "grpc client hsi disconnect failed" << std::endl;
    }
    return;
}

#ifdef __cplusplus
}
#endif