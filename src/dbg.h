/*\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\
  DBG.H

  Designed by THE on JUN 11, 2019
/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\*/

#ifndef _DBG_H_
#define _DBG_H_

#define	LOGDBG		 1U
#define LOGINFO		 2U
#define	LOGWARN		 3U
#define LOGERR		 4U
#define LOGUNKNOWN 0U

extern  char 		*PPP_state2str(U16 state);
extern  char 		*DHCP_state2str(U16 state);

/* log level, logfile fp, log msg */
#define VRG_LOG(lvl, fp, ccb, ccb2str, ...) LOGGER(LOG ## lvl, __FILE__, __LINE__, fp, ccb, ccb2str, __VA_ARGS__)

extern void LOGGER(U8 level, char *filename, int line_num, FILE *log_fp, void *ccb, void (*ccb2str)(void *, char *), const char *fmt,...);
char *loglvl2str(U8 level);
U8 logstr2lvl(const char *log_str);
extern void PPPLOGMSG(void *ccb, char *buf);
extern void DHCPLOGMSG(void *ccb, char *buf);
extern U8 vRG_dbg_flag;

#endif