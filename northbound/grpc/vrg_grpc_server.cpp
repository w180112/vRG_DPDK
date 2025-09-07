#include <iostream>
#include <grpc++/grpc++.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>
#include "vrg_grpc_cli.h"
#include "../../src/vrg.h"

#ifdef __cplusplus
extern "C" {
#endif

void vrg_grpc_server_run(void *arg) {
    VRG_t *vrg_ccb = (VRG_t *)arg;

    std::string server_address(vrg_ccb->unix_sock_path);
    std::cout << "grpc server starting..." << std::endl;
    grpc::ServerBuilder builder;

    grpc::EnableDefaultHealthCheckService(true);
    std::shared_ptr<grpc::ServerCredentials> ptr = grpc::InsecureServerCredentials();
    builder.AddListeningPort(server_address, ptr);
    VRGCLIServiceImpl vrg_service(vrg_ccb);
    builder.RegisterService(&vrg_service);

    std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
    std::cout << "grpc server listening on " << server_address << std::endl;
    server->Wait();
    return;
}

#ifdef __cplusplus
}
#endif
