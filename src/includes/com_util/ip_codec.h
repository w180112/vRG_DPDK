/*\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\
  IP_CODEC.H

  Designed by Dennis Tseng on Jan 1, 2003
/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\*/

#ifndef _IP_CODEC_H_
#define _IP_CODEC_H_

#define IP_VERSION             	4
#define IP_MIN_HDR_LEN         	5    /* in 32 bits */
#define MY_IP_TTL               0x40 
#define MAC_ADDR_LEN            6
#define IP_ADDR_LEN            	4
#define UDP_HDR_LEN             8
#define VLAN_TAG_LEN            4

/* protocol type */
#define FRAME_TYPE_ARP          0x0806
#define FRAME_TYPE_IP          	0x0800
#define PROTO_TYPE_ICMP         1
#define PROTO_TYPE_TCP          6
#define PROTO_TYPE_UDP          17
#define OP_ARP_REQ              1
#define OP_ARP_RSP              2   

/* frame, ip, udp */
#define ETH_HDR_LEN				12
#define ETH_TYPE_LEN			2
//#define	IP_LEN					20
#define	UDP_LEN					8
#define BOOT_REQUEST    		1
#define BOOT_REPLY				2
#define BOOT_CHADDR_LEN			16
#define BOOT_SNAME_LEN			64
#define BOOT_FILE_LEN	   		128
#define BOOT_VENDOR_LEN   		64
#define BOOT_SRV_PORT 			67 //0x43
#define BOOT_CLI_PORT 			68 //0x44

/*----------------------------------------------------------
 * IP packet 
 *---------------------------------------------------------*/
struct _IP_PACKET {
    struct VER_IHL {
#		ifdef _BIG_ENDIAN	
		U8      ver : 4; /* high nibble */
		U8      IHL : 4; /* IP Header Len - lower memory */
#		else /*_LIT_ENDIAN */   	
        U8      IHL : 4; /* IP Header Len - lower memory */
        U8      ver : 4; /* high nibble */
#		endif          
    } ver_ihl;
    U8      	tos;      /* type of service */
    U16     	total_len; /* includes header & data */
    U16     	id;
    struct FLAG_FRAG {
#		ifdef _BIG_ENDIAN	    	
        U16     flag : 3;
        U16     frag_off : 13;
#		else /*_LIT_ENDIAN */   	        
		U16     frag_off : 13;
		U16     flag : 3;
#		endif        
    } flag_frag;
    U8      	ttl;
    U8      	proto;
    U16     	head_chksum;
    U8 			cSA[IP_ADDR_LEN];
    U8 			cDA[IP_ADDR_LEN];
    U8      	*opt_pad;
    U8			*data;
};
typedef struct _IP_PACKET  tIP_PKT;
extern U8   	*ENCODE_IP_PKT(tIP_PKT *ip_pkt, U8 *cp);
extern STATUS 	DECODE_IP_PKT(tIP_PKT *ip_pkt, U8 *data, U16 *len);

/*----------------------------------------------------------
 * UDP packet 
 *---------------------------------------------------------*/
struct UDP_PACKET {
    U16     src;
    U16     dst;
    U16     len; /* includes header & data */
    U16     chksum;
    U8      *data;
};
typedef struct UDP_PACKET  tUDP_PKT;

extern U16 	CHECK_SUM(U32);
extern int  DECODE_UDP_PKT(tUDP_PKT *udp_pkt, tIP_PKT *ip_pkt, U16 *data_len);
extern U8   *ENCODE_UDP_PKT(tIP_PKT *ip_pkt, tUDP_PKT *udp_pkt, U8 *mp);
extern void DHCPR_encode_frame(U8 *dm, U8 *sm, U8 *dip, U8 *sip, UINT vid, U8 *im, UINT len, U8 *mu, UINT *mulen);

struct ARP_PACKET {
    U16     hardware; /* hardware type */
    U16     proto;    /* protocol type */
    U8      hlen;     /* hardware length */
    U8      plen;     /* protocol length */
    U16     op;
    U8      sa_mac[MAC_ADDR_LEN];  /* ethernet address */
    U8      sa_ip[IP_ADDR_LEN];
    U8      da_mac[MAC_ADDR_LEN];
    U8      da_ip[IP_ADDR_LEN];
};
typedef struct ARP_PACKET  tARP_PKT;
extern U8   *ENCODE_ARP_PKT(tARP_PKT *arp_pkt, U8 *cp);
#endif /* _IP_CODEC_H_ */
