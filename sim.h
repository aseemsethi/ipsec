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
#define IKEV2_SPI_LEN 8

typedef struct {
	int     curState;
    
    // Used for all recvd buffers
    char        rBuff[1024];
    int     rLen;
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
    char i_spi[IKEV2_SPI_LEN]; /* IKE_SA Initiator's SPI */
    char r_spi[IKEV2_SPI_LEN]; /* IKE_SA Responder's SPI */
    char next_payload;
    char version; /* MjVer | MnVer */
    char exchange_type;
    char flags;
    char message_id[4];
    char length[4]; /* total length of HDR + payloads */
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

