#include <common.h>
#include <errno.h>
#include <sys/un.h>

int client_socket;

STATUS init_unix_sock_client()
{
    client_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (client_socket == -1) {
        fprintf(stderr, "Error! Cannot create unix socket: %s\n", strerror(errno));
        return ERROR;
    }

    struct sockaddr_un server_addr;

    server_addr.sun_family = AF_UNIX;
    strcpy(server_addr.sun_path, "/var/run/vrg/vrg.sock");

    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        fprintf(stderr, "Error! Cannot connect to unix socket server: %s\n", strerror(errno));
        return ERROR;
    }

    return SUCCESS;
}

STATUS send_msg(void *msg, int len)
{
    if (write(client_socket, msg, len) < 0) {
        fprintf(stderr, "Error! Cannot send data to unix socket server: %s\n", strerror(errno));
        return ERROR;
    }

    return SUCCESS;
}