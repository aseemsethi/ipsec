#include "crypto/dh_groups.h"

#define IKEV2_NONCE_MAX_LEN 32
#define IKE_PKT_SIZE 512
#define IKEV2_SPI_LEN 8
#define PROPOSAL_LEN 8
#define IKEV2_MAX_HASH_LEN 20
#define AES_PARAM_SIZE 4
#define TRANSFORM_SIZE 8

/* Current IKEv2 version from RFC 4306 */
#define IKEV2_MjVer 2
#define IKEV2_MnVer 0
#ifdef CCNS_PL
#define IKEV2_VERSION ((IKEV2_MjVer) | ((IKEV2_MnVer) << 4))
#else /* CCNS_PL */
#define IKEV2_VERSION (((IKEV2_MjVer) << 4) | (IKEV2_MnVer))
#endif /* CCNS_PL */

/* IKEv2 Flags */
#define IKEV2_HDR_INITIATOR 0x08
#define IKEV2_HDR_VERSION   0x10
#define IKEV2_HDR_RESPONSE  0x20
/* Payload Header Flags */
#define IKEV2_PAYLOAD_FLAGS_CRITICAL 0x01

#define IKEV2_SPI_LEN 8

/* IKEv2 Exchange Types */
enum {
    /* 0-33 RESERVED */
    IKE_SA_INIT = 34,
    IKE_SA_AUTH = 35,
    CREATE_CHILD_SA = 36,
    INFORMATION = 37
    /* 38-239 RESERVED TO IANA */
    /* 240-255 Reserved for private use */
};


/* Identification Data Types (RFC 4306, Sect. 3.5) */
enum {
    ID_IPV4_ADDR = 1,
    ID_FQDN = 2,
    ID_RFC822_ADDR = 3,
    ID_IPV6_ADDR = 5,
    ID_DER_ASN1_DN = 9,
    ID_DER_ASN1_GN= 10,
    ID_KEY_ID = 11
};

#define REDIRECT_SUPPORTED 16406
#define REDIRECT_PAYLOAD 16407
#define REDIRECT_FROM 16408

/*
 *  * IKEV2 Payload Types
 *   */
enum {
    IKEV2_PAYLOAD_NO_NEXT_PAYLOAD = 0,
    IKEV2_PAYLOAD_SA = 33,
    IKEV2_PAYLOAD_KEY_EXCHANGE = 34,
    IKEV2_PAYLOAD_IDi = 35,
    IKEV2_PAYLOAD_IDr = 36,
    IKEV2_PAYLOAD_CERTIFICATE = 37,
    IKEV2_PAYLOAD_CERT_REQ = 38,
    IKEV2_PAYLOAD_AUTHENTICATION = 39,
    IKEV2_PAYLOAD_NONCE = 40,
    IKEV2_PAYLOAD_NOTIFICATION = 41,
    IKEV2_PAYLOAD_VENDOD_ID = 43,
    IKEV2_PAYLOAD_TSi = 44,
    IKEV2_PAYLOAD_TSr = 45,
    IKEV2_PAYLOAD_ENCRYPTED = 46,
    IKEV2_PAYLOAD_NEXT_FAST_ID = 121
};

/* IKEv2 Proposal - Protocol ID */
enum {
    IKEV2_PROTOCOL_RESERVED = 0,
    IKEV2_PROTOCOL_IKE = 1, /* IKE is the only one allowed for EAP-IKEv2 */
    IKEV2_PROTOCOL_AH = 2,
    IKEV2_PROTOCOL_ESP = 3
};

struct ikev2_payloads {
    unsigned char *sa;
    size_t sa_len;
    unsigned char *ke;
    size_t ke_len;
    unsigned char *idi;
    size_t idi_len;
    unsigned char *idr;
    size_t idr_len;
    unsigned char *cert;
    size_t cert_len;
    const u8 *auth;
    size_t auth_len;
    unsigned char*nonce;
    size_t nonce_len;
    const u8 *encrypted;
    size_t encrypted_len;
    u8 encr_next_payload;
    const u8 *notification;
    size_t notification_len;
    unsigned char* redirect;
    size_t redirect_len;
};


struct ikev2_proposal_data {
    u8 proposal_num;
    int integ;
    int prf;
    int encr;
    int dh;
};

#define PAYLOAD_HDR_SIZE 4
typedef struct {
    u8 next_payload;
    u8 flags;
    u8 payload_length[2]; /* this payload, including the payload header */
} ikev2_payload_hdr;

typedef struct ikev2_proposal {
    u8 type; /* 0 (last) or 2 (more) */
    u8 reserved;
    u8 proposal_length[2]; /* including all transform and attributes */
    u8 proposal_num;
    u8 protocol_id; /* IKEV2_PROTOCOL_* */
    u8 spi_size;
    u8 num_transforms;
    /* SPI of spi_size octets */
    /* Transforms */
} ikev2_proposal;


typedef struct ikev2_transform {
    u8 type; /* 0 (last) or 3 (more) */
    u8 reserved;
    u8 transform_length[2]; /* including Header and Attributes */
    u8 transform_type;
    u8 reserved2;
    u8 transform_id[2];
    /* Transform Attributes */
} ikev2_transform;

/* IKEv2 Transform Types */
enum {
    IKEV2_TRANSFORM_ENCR = 1,
    IKEV2_TRANSFORM_PRF = 2,
    IKEV2_TRANSFORM_INTEG = 3,
    IKEV2_TRANSFORM_DH = 4,
    IKEV2_TRANSFORM_ESN = 5
};


/* IKEv2 Tranform Type 1 (Encryption Algorithm) */
enum {
    ENCR_DES_IV64 = 1,
    ENCR_DES = 2,
    ENCR_3DES = 3,
    ENCR_RC5 = 4,
    ENCR_IDEA = 5,
    ENCR_CAST = 6,
    ENCR_BLOWFISH = 7,
    ENCR_3IDEA = 8,
    ENCR_DES_IV32 = 9,
    ENCR_NULL = 11,
    ENCR_AES_CBC = 12,
    ENCR_AES_CTR = 13
};

/* IKEv2 Transform Type 2 (Pseudo-random Function) */
enum {
    PRF_HMAC_MD5 = 1,
    PRF_HMAC_SHA1 = 2,
    PRF_HMAC_TIGER = 3,
    PRF_AES128_XCBC = 4
};

/* IKEv2 Transform Type 3 (Integrity Algorithm) */
enum {
    AUTH_HMAC_MD5_96 = 1,
    AUTH_HMAC_SHA1_96 = 2,
    AUTH_DES_MAC = 3,
    AUTH_KPDK_MD5 = 4,
    AUTH_AES_XCBC_96 = 5
};

/* IKEv2 Transform Type 4 (Diffie-Hellman Group) */
enum {
    DH_GROUP1_768BIT_MODP = 1, /* RFC 4306 */
    DH_GROUP2_1024BIT_MODP = 2, /* RFC 4306 */
    DH_GROUP5_1536BIT_MODP = 5, /* RFC 3526 */
    DH_GROUP5_2048BIT_MODP = 14, /* RFC 3526 */
    DH_GROUP5_3072BIT_MODP = 15, /* RFC 3526 */
    DH_GROUP5_4096BIT_MODP = 16, /* RFC 3526 */
    DH_GROUP5_6144BIT_MODP = 17, /* RFC 3526 */
    DH_GROUP5_8192BIT_MODP = 18 /* RFC 3526 */
};

/* Authentication Method (RFC 4306, Sect. 3.8) */
enum {
    AUTH_RSA_SIGN = 1,
    AUTH_SHARED_KEY_MIC = 2,
    AUTH_DSS_SIGN = 3
};

typedef struct ikev2_trafficSelec {
    u8 type; /* 7 for IPv4 */
    u8 proto; // 0 
    u8 ts_length[2]; /* including Header and Attributes */
    u8 start_port[2]; // 0
    u8 end_port[2]; // 0
    u32 startIP;
    u32 endIP;
} ikev2_trafficSelec;


struct ikev2_integ_alg {
    int id;
    size_t key_len;
    size_t hash_len;
};

struct ikev2_prf_alg {
    int id;
    size_t key_len;
    size_t hash_len;
};

struct ikev2_encr_alg {
    int id;
    size_t key_len;
    size_t block_size;
};

