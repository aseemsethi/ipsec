#include "stdio.h"
#include "stdlib.h"
#include <sys/socket.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h> // for iphdr
#include <arpa/inet.h>
#include <netdb.h>  // for hostent
#include <net/ethernet.h> // for ETH_P_ALL
#include <linux/if_packet.h> // for sll
#include <net/if.h>

typedef unsigned short u16;
typedef unsigned short ushort;
typedef unsigned long u32;
typedef unsigned char uchar;
typedef unsigned char u8;

#include "ikev2.h"


#define TRUE 1
#define FALSE 0
#define IPV4_UDP_SIZE 28
#define IPV6_UDP_SIZE 48 


// IKE STATES
#define NO_CHANGE 4
#define IKE_START_STATE 0
#define IKE_INIT_STATE 1
#define IKE_AUTH_STATE 2
#define IKE_ESTAB_STATE 3

#define INIT_EVENT 0
#define TIMEOUT_EVENT 1
#define DATA_EVENT 2
#define REDIRECT_EVENT 3

#define FSM_Q_SIZE 1000
#define IPV4_UDP_LEN 28

struct udpheader {
 unsigned short int udph_srcport;
 unsigned short int udph_destport;
 unsigned short int udph_len;
 unsigned short int udph_chksum;
};

struct ikev2_keys {
    u8 *SK_d, *SK_ai, *SK_ar, *SK_ei, *SK_er, *SK_pi, *SK_pr;
    size_t SK_d_len, SK_integ_len, SK_encr_len, SK_prf_len;
};

typedef struct {
	int     curState;
    char    srcIP[20];
    int     srcPort;
    
    // Used for all recvd buffers
    char        rBuff[1024];
    int     rLen;

	// IKEv2 specific variable
    u8      i_spi[IKEV2_SPI_LEN]; /* IKE_SA Initiator's SPI */
    u8      r_spi[IKEV2_SPI_LEN]; /* IKE_SA Responder's SPI */

    struct      ikev2_payloads payloads;
    struct      ikev2_proposal_data ourProp;  // what we we propose
    struct      ikev2_proposal_data prop;  // what we recvd from peer

    unsigned char       *i_dh_private;
    size_t      r_dh_public_len;
    struct      dh_group *dh;
    u8			i_nonce[IKEV2_NONCE_MAX_LEN];
    size_t      i_nonce_len;
    // Have we been re-drected ? This var is TRUE, if yes
    int redirected;
    u32 redirected_ip;
    struct      ikev2_keys keys;
    u8      	*IDi;
    size_t      IDi_len;
    void        *cb_ctx;
    void        *shared_secret;
    int     	shared_secret_len;
    unsigned char   user_password[10];
    int     	user_password_len;
    unsigned char   *shared;
    int     	shared_len;
    u8      	*key_pad;
    size_t      key_pad_len;

    // save the SA_INIT pkt for any retransmits
    char        saInitBuff[1024];
    int			saInitLen;

    // Child SA SPIs
    u32 		child_i_spi;
    u32 		child_r_spi;
    // Recvd from Responders
    char        *r_dh_public; 
    u8      	*IDr;
    size_t      IDr_len;
    char        *r_nonce;
    int     	r_nonce_len;

} ikeStruct;

typedef struct {
    int         sock;
    struct      sockaddr_in server_addr;
    struct      sockaddr_ll sll;
    char        utIP[20];
    char        selfIP[20];
    ikeStruct   ike;

    // NetLink socket
    int     nlsock;
    int     nl_seqNum;
} ipsecCfg;

typedef struct {
    u8 i_spi[IKEV2_SPI_LEN]; /* IKE_SA Initiator's SPI */
    u8 r_spi[IKEV2_SPI_LEN]; /* IKE_SA Responder's SPI */
    u8 next_payload;
    u8 version; /* MjVer | MnVer */
    u8 exchange_type;
    u8 flags;
    u8 message_id[4];
    u8 length[4]; /* total length of HDR + payloads */
} ikev2_hdr;

#define PUT_BE32(a, val)                    \
    do {                            \
        (a)[0] = (u8) ((((u32) (val)) >> 24) & 0xff);   \
        (a)[1] = (u8) ((((u32) (val)) >> 16) & 0xff);   \
        (a)[2] = (u8) ((((u32) (val)) >> 8) & 0xff);    \
        (a)[3] = (u8) (((u32) (val)) & 0xff);       \
    } while (0)

#define PUT_BE16(a, val)            \
    do {                    \
        (a)[0] = ((u16) (val)) >> 8;    \
        (a)[1] = ((u16) (val)) & 0xff;  \
    } while (0)

#define GET_BE32(a) ((((u32) (a)[0]) << 24) | (((u32) (a)[1]) << 16) | \
                             (((u32) (a)[2]) << 8) | ((u32) (a)[3]))
#define GET_BE16(a) ((u16) (((a)[0] << 8) | (a)[1]))

int ikeStart(ikeStruct*, int, unsigned char*);
