extern void drv_xmit(U8 *mu, U16 mulen);
extern int ppp_recvd(void);
extern int decapsulation(void);
extern int gateway(void);
extern int PPP_PORT_INIT(uint16_t port);
extern int control_plane_dequeue(tPPP_MBX **mail);