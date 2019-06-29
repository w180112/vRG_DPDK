/*\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\
  UTIL.H
    the common utilities of all files are saved in this file.
/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\*/

#ifndef __UTIL_H__
#define __UTIL_H__

#ifdef __cplusplus
extern "C" {
#endif
extern char *GetStrTok(char **cpp, char *delimiters);
extern int  get_local_ip(U8 *ip, char *sif);
extern int  set_local_ip(char *ip_str, char *sif);

extern U8	*DECODE_U16(U16 *val, U8 *mp);
extern U8	*DECODE_U24(U32 *val, U8 *mp);
extern U8	*DECODE_U32(U32 *val, U8 *mp);

extern U8	*ENCODE_U16(U8 *mp, U16 val);
extern U8	*ENCODE_U24(U8 *mp, U32 val);
extern U8	*ENCODE_U32(U8 *mp, U32 val);

extern void PRINT_MESSAGE(unsigned char*, int);
extern U16 	ADD_CARRY_FOR_CHKSUM(U32 sum);
extern U16 	CHECK_SUM(U32);

#ifdef __cplusplus
}
#endif

#endif
