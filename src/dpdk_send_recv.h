extern void drv_xmit(U8 *mu, U16 mulen);
extern int ppp_recvd(void);
extern int encapsulation(void);
extern int PPP_PORT_INIT(uint16_t port);
extern tPPP_MBX *control_plane_dequeue(tPPP_MBX *mail);