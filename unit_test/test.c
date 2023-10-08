#include <common.h>
#include "test.h"

int main()
{
    signal(SIGCHLD, SIG_IGN);

    puts("====================start unit tests====================\n");
    puts("====================test codec.c====================");
    test_build_padi();
    puts("ok!");

    puts("\nall test successfully");
    puts("====================end of unit tests====================");
}
