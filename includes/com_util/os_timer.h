/*\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\
  OS_TIMER.H 

  Designed by Dennis Tseng on Apr 16,'01
/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\*/

#ifndef _OS_TIMER_H_
#define _OS_TIMER_H_

#define SEC                 (1000000)

#define MAX_TMR_CB_NUM   	1200

/*-------------------------------------------------
 *            Timer Block
 *------------------------------------------------*/
typedef struct _TMR_CB  *pTMR_CB; 
typedef struct _TMR_CB  tTMR_CB;
struct _TMR_CB {
	char        tmr_name[30]; /* identify owner */
    U32         timeleft;
    U8			event;
    void        *ccb;
    tIPC_ID		Que; /* It is a pointer */
    pTMR_CB     next;
    BOOL     	idle;
};

typedef struct _TMR_CBs  tTMR_CBs;
struct _TMR_CBs {
	tTMR_CB  	tcb[MAX_TMR_CB_NUM];
    pTMR_CB     tmrHdr;
};

typedef struct _TMR_OBJ  tTMR_OBJ;
struct _TMR_OBJ {
	tTMR_CBs	*shm;
};
   			
/*-------------------------------------------------------------
 *      Define variable and procedures
 *
 * [extern "C"] must be defined here when other "C" file
 * wants to call the following "C" functions located
 * in a "C++" file.
 *
 * However, do not put [extern "C"] in "C" file, which will result
 * in compiler error.
 * 
 * gcc compiler will define "__cplusplus" reserved word automatically.
 *
 * Similarily, when "C++" wants to call "C" function, [extern "C"]
 * must also be defined in "C++" file.
 *-------------------------------------------------------------*/
/* Normally, "_cplusplus" only applied in .h file, just because
only .h file could be included in either .c or .cpp file */ 

extern tTMR_OBJ		tmrObj;		
extern tIPC_ID		tmr_semid,tmr_shmid,tmrQ;
extern void 		tmrExit(void);
extern int   		tmrTid;
extern char     	*SYS_UP_CTIME(void),*SYS_UP_TIME(void),*_2CTIME(U64);
extern void         _SEC2CTIME(U64,char*);
extern void         _SEC2STR_TIME(U64,char*);

extern int 			tmrInit(void);
extern STATUS       OSTMR_InitTmrCbs(void);
extern pTMR_CB      OSTMR_MallocTmrCb(void);
extern void         OSTMR_FreeTmrCb(pTMR_CB p);
extern void         OSTMR_StartTmr(tIPC_ID Que, void *ccb, U32 delay, char *name, U16 event);
extern void         OSTMR_StopTmrs(void *ccb);
extern void         OSTMR_StopXtmr(void *ccb, U16 event);
extern BOOL         OSTMR_IsTmrListEmpty(void);
extern BOOL         OSTMR_IsTmrExist(void *ccb, U16 event);

#endif /* _OS_TIMER_H_ */
