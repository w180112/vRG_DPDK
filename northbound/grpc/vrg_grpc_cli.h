#include <grpc++/grpc++.h>
#include "vrg_cli.grpc.pb.h"

using namespace std;
using namespace vrgcliservice;

class VRGCLIServiceImpl final : public vrgcliservice::VrgService::Service
{
    public:
    explicit VRGCLIServiceImpl() {}

    ::grpc::Status ConnectHsi(::grpc::ServerContext* context, const ::vrgcliservice::HsiRequest* request, ::vrgcliservice::HsiReply* response) override;
    ::grpc::Status DisconnectHsi(::grpc::ServerContext* context, const ::vrgcliservice::HsiRequest* request, ::vrgcliservice::HsiReply* response) override;
};