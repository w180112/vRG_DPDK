#include <iostream>
#include "../vrg.h"

VRG_t *vrg_ccb;

void vrg_grpc_server_run() {
    std::string server_address("0.0.0.0:50051");

    std::cout << "Server listening on " << server_address << std::endl;
    for(;;); //place holder for grpc server
}

int main(int argc, char **argv) {
    vrg_grpc_server_run();

    return 0;
}