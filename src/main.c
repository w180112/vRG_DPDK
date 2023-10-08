#include <stdio.h>
#include <common.h>
#include "vrg.h"

int main(int argc, char **argv)
{	
	if (argc < 5) {
		puts("Too less parameter.");
		puts("Type vrg <eal_options>");
		return ERROR;
	}
    return vrg_start(argc, argv);
}