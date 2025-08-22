#include <grpc++/grpc++.h>
#include "vrg_grpc_cli.h"

#ifdef __cplusplus
extern "C" 
{
#endif

#include "../../src/vrg.h"

typedef struct cli_to_main_msg {
	U8 type;
	U8 user_id;
}cli_to_main_msg_t;

#ifdef __cplusplus
}
#endif

using namespace std;
using namespace vrgcliservice;

extern struct rte_ring *rte_ring;

grpc::Status VRGCLIServiceImpl::ConnectHsi(::grpc::ServerContext* context, const ::vrgcliservice::HsiRequest* request, ::vrgcliservice::HsiReply* response)
{
    cout << "ConnectHsi called" << endl;
    tVRG_MBX *mail = (tVRG_MBX *)malloc(sizeof(tVRG_MBX));
    cli_to_main_msg_t *msg = (cli_to_main_msg_t *)mail->refp;
    mail->type = IPC_EV_TYPE_CLI;
	mail->len = sizeof(cli_to_main_msg_t);
    msg->user_id = request->user_id();
    msg->type = CLI_CONNECT;
    vrg_ring_enqueue(rte_ring, (void **)&mail, 1);
    return grpc::Status::OK;
}

grpc::Status VRGCLIServiceImpl::DisconnectHsi(::grpc::ServerContext* context, const ::vrgcliservice::HsiRequest* request, ::vrgcliservice::HsiReply* response)
{
    cout << "DisconnectHsi called" << endl;
    tVRG_MBX *mail = (tVRG_MBX *)malloc(sizeof(tVRG_MBX));
    cli_to_main_msg_t *msg = (cli_to_main_msg_t *)mail->refp;
    mail->type = IPC_EV_TYPE_CLI;
	mail->len = sizeof(cli_to_main_msg_t);
    msg->user_id = request->user_id();
    msg->type = CLI_DISCONNECT;
    vrg_ring_enqueue(rte_ring, (void **)&mail, 1);
    return grpc::Status::OK;
}

grpc::Status VRGCLIServiceImpl::DhcpServerStart(::grpc::ServerContext* context, const ::vrgcliservice::DhcpServerRequest* request, ::vrgcliservice::DhcpServerReply* response)
{
    cout << "DhcpServerStart called" << endl;
    tVRG_MBX *mail = (tVRG_MBX *)malloc(sizeof(tVRG_MBX));
    cli_to_main_msg_t *msg = (cli_to_main_msg_t *)mail->refp;
    mail->type = IPC_EV_TYPE_CLI;
	mail->len = sizeof(cli_to_main_msg_t);
    msg->user_id = request->user_id();
    msg->type = CLI_DHCP_START;
    vrg_ring_enqueue(rte_ring, (void **)&mail, 1);
    return grpc::Status::OK;
}

grpc::Status VRGCLIServiceImpl::DhcpServerStop(::grpc::ServerContext* context, const ::vrgcliservice::DhcpServerRequest* request, ::vrgcliservice::DhcpServerReply* response)
{
    cout << "DhcpServerStop called" << endl;
    tVRG_MBX *mail = (tVRG_MBX *)malloc(sizeof(tVRG_MBX));
    cli_to_main_msg_t *msg = (cli_to_main_msg_t *)mail->refp;
    mail->type = IPC_EV_TYPE_CLI;
	mail->len = sizeof(cli_to_main_msg_t);
    msg->user_id = request->user_id();
    msg->type = CLI_DHCP_STOP;
    vrg_ring_enqueue(rte_ring, (void **)&mail, 1);
    return grpc::Status::OK;
}
