extern void drv_xmit(U8 *mu, U16 mulen);
extern int ppp_recvd(void);
extern int uplink(void);
extern int downlink(void);
extern int rg_func(void);
extern int gateway(void);
extern int PPP_PORT_INIT(uint16_t port/*, uint32_t lcore_id*/);
extern int control_plane_dequeue(tPPP_MBX **mail);