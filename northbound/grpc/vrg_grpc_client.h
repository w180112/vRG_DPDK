#ifndef VRG_GRPC_SERVER_H
#define VRG_GRPC_CLIENT_H

#include <common.h>

#ifdef __cplusplus
extern "C" {
#endif

void vrg_grpc_client_connect(char *server_address);
void vrg_grpc_hsi_connect(U8 user_id);
void vrg_grpc_hsi_disconnect(U8 user_id);

#ifdef __cplusplus
}
#endif

#endif // VRG_GRPC_CLIENT_H