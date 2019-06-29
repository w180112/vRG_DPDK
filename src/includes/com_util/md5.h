/* MD5.H - header file for MD5C.C
 */

#ifndef _MD5_H_
#define	_MD5_H_

/* MD5 context. */
typedef struct {
  U32 state[4];  /* state (ABCD) */
  U32 count[2];  /* number of bits, modulo 2^64 (lsb first) */
  unsigned char buffer[64];  /* input buffer */
} MD5_CTX;

void MD5Init(MD5_CTX*);
void MD5Update(MD5_CTX*, U8*, U16);
void MD5Final(U8*, MD5_CTX*);

extern void hmac_md5(U8 *text, int text_len, U8 *key, int key_len, U8 *digest);
#endif
