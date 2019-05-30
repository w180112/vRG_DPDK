/*\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\
  COMMON.H
    the common utilities of all files are saved in this file.
/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\*/

#ifndef _COMMON_H_
#define _COMMON_H_

#include	    <tgmath.h> 

#ifdef __cplusplus
extern "C" {
#endif

#include        <stdio.h>
#include        <string.h>
#include	    <stdlib.h>

#define         UNIX_VERSION    
#define		    _LIT_ENDIAN //_BIG_ENDIAN or _LIT_ENDIAN   

#ifdef          UNIX_VERSION
/*-----------------------------------
 *            UNIX
 *----------------------------------*/
#include	    <stdarg.h>
#include	    <fcntl.h>
#include        <unistd.h> /* fork() */
#include	    <signal.h>
#include	    <time.h>
#include        <sys/wait.h> /* wait */
#include        <sys/types.h>
#include	    <sys/ioctl.h> /* get local ip */
#include		<assert.h>

#include	    <pthread.h>
#include        <semaphore.h>
#include	    <sys/ipc.h>
#include	    <sys/shm.h>
#include	    <sys/sem.h>
#include	    <sys/msg.h>
#include 	    <sys/time.h>
#include 	    <sys/times.h>
#include	    <sys/param.h>
#include        <sys/socket.h>
#include        <netinet/in.h> /* get local ip */ 
#include	    <net/if.h>     /* get local ip */
#include	    <linux/if_packet.h>
#include 		</usr/include/linux/filter.h>
//#include 		"../../uClibc-0.9.28/_install/usr/arm-linux-uclibc/usr/include/linux/filter.h"
#include 		<linux/if_ether.h>
#include        <arpa/inet.h> /* inet_addr(), struct sockaddr_in */
#include	    <netdb.h>
#include	    <termio.h>
#include        <malloc.h>
#include        <memory.h>
//#include		"/uClibc-0.9.28/include/pthread.h"
#include		<pthread.h>

typedef  		unsigned char   	BOOL;
typedef  		short				STATUS;
typedef  		int    				(*FUNCPTR)(void);       //return int
typedef  		unsigned char		(*U8FUNCPTR)(void);     //return U8
typedef  		void   				(*VOIDFUNCPTR)(void);   //return void

#define         ADV_TRUE           	1
#define         ADV_FALSE          	0
#define         SUCCESS            	0

#define 		TRILL_WAN_PORT		48
#define			TRILL_MAX_PORT_NUM	48

#define         ERROR             	-1
#define         ADV_ERR             ERROR;
#define         _BUCKET(x)         	(x & 0x0F) 

#define			MTU					1500
#define 		ERROR   			-1

#define 		MSG_BUF 			80

//#pragma pack(push)				/* push current alignment to stack */
#pragma 		pack(1) 			/* set alignment to 1 byte boundary */
//struct ....
//#pragma pack(pop) 				/* restore original alignment from stack */

#endif


/*******************************************
 * COMMON
 *******************************************/
typedef unsigned char       BIT;
typedef signed char         BYTE;
typedef signed char         BIT8;
typedef short 			    BIT16;

typedef unsigned char       U8;
typedef U8                  u8;
typedef unsigned short      U16;
typedef U16                 u16;

/*typedef  U8                 mac_addr_t[6];   */
#ifdef  UNIX_VERSION
typedef unsigned int        U24;
typedef unsigned int        U32;
typedef U32					u32;
typedef U32                 L7_uint32;
typedef int                 BIT32;
typedef int					tIPC_ID;

typedef enum {
	FALSE,
	TRUE
} L7_BOOL;

// abi, modified, 20070412
//typedef unsigned long       U64; /* = ULONG in VxWorks */
typedef unsigned long long  U64;
// abi, end
#endif

typedef unsigned int	    UINT;	
typedef U8                  (*U8_FUNCPTR)(void);
typedef U16                 (*U16_FUNCPTR)(void);      /* return U16 */
typedef U32                 (*U32_FUNCPTR)(void);      /* return U32 */
typedef void                (*VOID_FUNCPTR)(void);      /* return U32 */

typedef U8                  *(*U8PTR_FUNCPTR)(void);   /* return U8 ptr */
typedef U32                 *(*U32PTR_FUNCPTR)(void);  /* return U32 ptr */
typedef void                *(*VOIDPTR_FUNCPTR)(void); /* return void ptr */
typedef char                *(*STRFUNCPTR)(void);      /* return char ptr */
typedef void 				(*SIG_FUNCPTR)(int);
    
#define W1                  1   /* debug warnning level */
#define W2                  2
#define W3                  3
#define HASH_SIZE           16   

#include                    "ipc.h"
#include                    "os_timer.h"
#include		            "util.h"
#include					"ip_codec.h"
#include					"md5.h"

/********************************************************************
 * OS_DBG()
 *
 ********************************************************************/
#define OS_DBG(exp) ((exp) ? \
    printf("dbg> (%s), %s : %d\n\r",#exp, __FILE__, __LINE__) : 0)

/********************************************************************
 * mail
 ********************************************************************/
typedef struct _T_MAIL { 
	char    data[1500];
	int     type;
	int		evt;
	void    *ccb; 
	int     who; 
} tMAIL;

#ifdef __cplusplus
}
#endif

#endif
