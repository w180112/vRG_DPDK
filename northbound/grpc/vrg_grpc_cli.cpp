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

grpc::Status VRGCLIServiceImpl::ConnectHsi(::grpc::ServerContext* context, const ::vrgcliservice::HsiRequest* request, ::vrgcliservice::HsiReply* response)
{
    cout << "ConnectHsi called" << endl;
    tVRG_MBX mail;
    cli_to_main_msg_t *msg = (cli_to_main_msg_t *)mail.refp;
    mail.type = IPC_EV_TYPE_CLI;
	mail.len = sizeof(cli_to_main_msg_t);
    msg->user_id = request->user_id();
    msg->type = IPC_EV_TYPE_CLI;
    return grpc::Status::OK;
}

grpc::Status VRGCLIServiceImpl::DisconnectHsi(::grpc::ServerContext* context, const ::vrgcliservice::HsiRequest* request, ::vrgcliservice::HsiReply* response)
{
    cout << "DisconnectHsi called" << endl;
    return grpc::Status::OK;
}