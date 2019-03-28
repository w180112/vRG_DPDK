/*\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\
  IPC.H for COM

  Designed by Dennis Tseng on Apr 16,'01
/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\*/

#ifndef _IPC_H_
#define _IPC_H_

/* Normally, "_cplusplus" only applied in ".h" file, just because
only ".h" file could be included in either ".c" or ".cpp" file */
#ifdef __cplusplus 
extern "C" { /* in .cpp file, only this line is enough */
#endif

#define MAX_IPC_NUM			64
#define IPC_TYPE_MSGQ   	1
#define IPC_TYPE_SEM    	2
#define IPC_TYPE_SHM    	3
#define IPC_DEF_USR			10 //process id

#define	IPC_DEF_QID			0

enum {
	IPC_EV_TYPE_DEF,
	IPC_EV_TYPE_WEB,
	IPC_EV_TYPE_CLI,
	IPC_EV_TYPE_DRV,
	IPC_EV_TYPE_TMR,
	IPC_EV_TYPE_OAM,
	IPC_EV_TYPE_REG,
	IPC_EV_TYPE_MAP,
} IPC_TYPE;

typedef struct {
	tIPC_ID	qid;
	int		pid;
	key_t	key;
	char	name[80];
	int		type;
	BOOL	valid;
} tIPC_TBL;
	
typedef struct {
	U16  	type;
	U8 		evt;
    void	*ccb;
} tIPC_PRIM;

typedef struct {
	long  	DA;
    U8  	mtext[1518];
    long   	SA;
} tMBUF;

/*-------------------------------------------------
 *      Define variable and procedures
 *------------------------------------------------*/
extern struct 	IPC_KEY 	*ipc_key_shm;
extern key_t  	REG_IPC_KEY(U8 type);
extern tIPC_ID  ipc_reg(U8 type, key_t key, char*);
extern void  	p(int semid);
extern void  	v(int semid);
extern void  	*GET_SHM(tIPC_ID*, key_t, int);
extern void     DEL_SHM(tIPC_ID);
extern STATUS  	GET_SEM(tIPC_ID*, key_t, int);
extern STATUS	GET_MSGQ(tIPC_ID*, key_t);
extern STATUS	RCV_MSGQ(tIPC_ID, U8*, int*);
extern STATUS	SND_MSGQ(tIPC_ID, U8*, int);
extern STATUS 	SND_MSGQT2(tIPC_ID qid, tMBUF *mbuf);

extern STATUS	DEL_MSGQ(tIPC_ID);
extern STATUS	ipc_reply(tIPC_ID, tMBUF*);
extern STATUS   RCV_MSGQT(tIPC_ID, void*, int*, int);
extern STATUS  	ipc_sendw(tIPC_ID, void*, int, int, int);
extern STATUS 	ipc_send2who(tIPC_ID qid, void *data, int len, int who);
extern tIPC_ID 	ipc_map(key_t key);
extern STATUS	ipc_rcv(tIPC_ID, U8 *msg, int *mlen);
extern STATUS 	ipc_rcv2(tIPC_ID, tMBUF*, int *mlen);
extern STATUS 	ipc_sw(tIPC_ID, void *data, int size, int to);

#ifdef __cplusplus 
}
#endif

#endif /* _IPC_H_ */
