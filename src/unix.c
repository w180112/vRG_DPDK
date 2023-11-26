#include <common.h>
#include <sys/un.h>
#include "vrg.h"
#include "dbg.h"

STATUS init_unix_sock(VRG_t *vrg_ccb)
{
    remove(vrg_ccb->unix_sock_path);

    int server_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_socket == -1) {
        VRG_LOG(ERR, vrg_ccb->fp, NULL, NULL, "Error! Cannot create unix socket: %s", strerror(errno));
        return ERROR;
    }

    struct sockaddr_un server_addr;
    int server_len = sizeof(server_addr);
    struct sockaddr_un client_addr;
    unsigned int client_len = sizeof(client_addr);

    server_addr.sun_family = AF_UNIX;
    strcpy(server_addr.sun_path, vrg_ccb->unix_sock_path);

    bind(server_socket, (struct sockaddr *) &server_addr, server_len);

    listen(server_socket, 1);
    VRG_LOG(INFO, vrg_ccb->fp, NULL, NULL, "Unix socket server is listening");

    for(;;) {
        int client_socket = accept(server_socket, (struct sockaddr *) &client_addr, &client_len);
        if (client_socket == -1) {
            VRG_LOG(ERR, vrg_ccb->fp, NULL, NULL, "Error! Cannot accept unix socket client: %s", strerror(errno));
            continue;
        }
        for(;;) {
            char buf[1024];
            int len = recv(client_socket, buf, 1024, 0);
            if (len == -1) {
                VRG_LOG(ERR, vrg_ccb->fp, NULL, NULL, "Error! Cannot receive data from unix socket client: %s", strerror(errno));
                break;
            }
            if (len == 0) {
                VRG_LOG(WARN, vrg_ccb->fp, NULL, NULL, "Unix socket client disconnected");
                break;
            }

            send(client_socket, buf, len, 0);
        }
    }

    return SUCCESS;
}