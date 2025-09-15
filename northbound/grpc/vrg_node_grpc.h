#include <grpc++/grpc++.h>
#include "vrg_node.grpc.pb.h"
#include "../../src/vrg.h"

using namespace std;
using namespace vrgnodeservice;

class VRGNodeServiceImpl final : public vrgnodeservice::VrgService::Service
{
    public:
    explicit VRGNodeServiceImpl(VRG_t* ctx) : vrg_ccb(ctx) {}

    ::grpc::Status ConnectHsi(::grpc::ServerContext* context, const ::vrgnodeservice::HsiRequest* request, ::vrgnodeservice::HsiReply* response) override;
    ::grpc::Status DisconnectHsi(::grpc::ServerContext* context, const ::vrgnodeservice::HsiRequest* request, ::vrgnodeservice::HsiReply* response) override;
    ::grpc::Status DhcpServerStart(::grpc::ServerContext* context, const ::vrgnodeservice::DhcpServerRequest* request, ::vrgnodeservice::DhcpServerReply* response) override;
    ::grpc::Status DhcpServerStop(::grpc::ServerContext* context, const ::vrgnodeservice::DhcpServerRequest* request, ::vrgnodeservice::DhcpServerReply* response) override;
    ::grpc::Status GetVrgSystemInfo(::grpc::ServerContext* context, const ::google::protobuf::Empty* request, ::vrgnodeservice::VrgSystemInfo* response) override;
    ::grpc::Status GetVrgHsiInfo(::grpc::ServerContext* context, const ::google::protobuf::Empty* request, ::vrgnodeservice::VrgHsiInfo* response) override;
    ::grpc::Status GetVrgDhcpInfo(::grpc::ServerContext* context, const ::google::protobuf::Empty* request, ::vrgnodeservice::VrgDhcpInfo* response) override;

    private:
    VRG_t* vrg_ccb;
};