#ifndef _SOCK_H_
#define _SOCK_H_

#include <common.h>

STATUS init_unix_sock_client(void);
STATUS send_msg(void *msg, int len);

#endif