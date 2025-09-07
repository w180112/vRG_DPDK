#include <grpc++/grpc++.h>
#include "vrg_cli.grpc.pb.h"
#include "../../src/vrg.h"

using namespace std;
using namespace vrgcliservice;

class VRGCLIServiceImpl final : public vrgcliservice::VrgService::Service
{
    public:
    explicit VRGCLIServiceImpl(VRG_t* ctx) : vrg_ccb(ctx) {}

    ::grpc::Status ConnectHsi(::grpc::ServerContext* context, const ::vrgcliservice::HsiRequest* request, ::vrgcliservice::HsiReply* response) override;
    ::grpc::Status DisconnectHsi(::grpc::ServerContext* context, const ::vrgcliservice::HsiRequest* request, ::vrgcliservice::HsiReply* response) override;
    ::grpc::Status DhcpServerStart(::grpc::ServerContext* context, const ::vrgcliservice::DhcpServerRequest* request, ::vrgcliservice::DhcpServerReply* response) override;
    ::grpc::Status DhcpServerStop(::grpc::ServerContext* context, const ::vrgcliservice::DhcpServerRequest* request, ::vrgcliservice::DhcpServerReply* response) override;

    private:
    VRG_t* vrg_ccb;
};