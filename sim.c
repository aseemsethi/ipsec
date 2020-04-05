#include "sim.h"

ipsecCfg cfg;

typedef struct {
	int ikeEvent;
	void *ike;
	unsigned char *fsmBuff;
} fsmParam;

fsmParam *ikeFsmQ[FSM_Q_SIZE];
int ikeFsmQHead = 0;
int ikeFsmQTail = 0;

const struct ikev2_integ_alg * ikev2_get_integ(int);
const struct ikev2_encr_alg * ikev2_get_encr(int);
const struct ikev2_prf_alg * ikev2_get_prf(int);
void* getBuff(int);

char* payloadToString(int pl) {
    switch(pl) {
    case IKEV2_PAYLOAD_TSi:return "TSi";
    case IKEV2_PAYLOAD_TSr:return "TSr";
    case 16403: return "Auth LifeTime";
    case 16404: return "MultipleAuth Supported";
    case REDIRECT_PAYLOAD: return "Redirect Payload";
    default: return "unknown";
    }
}

char* eventToString(int event) {
    switch(event) {
    case 0: return "INIT_EVENT";
    case 1: return "TIMEOUT_EVENT";
    case 2: return "DATA_EVENT";
    default: return "UNKNOWN EVENT";
    }
}
char* stateToString(int state) {
    switch(state) {
    case 0: return "IKE_START_STATE";
    case 1: return "IKE_INIT_STATE";
    case 2: return "IKE_AUTH_STATE";
    case 3: return "IKE_ESTAB_STATE";
    default: return "UNKNOWN STATE";
    }
}

u8 * ikev2_decrypt_payload(int encr_id, int integ_id,
               struct ikev2_keys *keys, int initiator,
               ikev2_hdr *hdr,
               const u8 *encrypted, size_t encrypted_len,
               size_t *res_len)
{
    size_t iv_len;
    const u8 *pos, *end, *iv, *integ;
    u8 hash[IKEV2_MAX_HASH_LEN], *decrypted;
    size_t decrypted_len, pad_len;
    const struct ikev2_integ_alg *integ_alg;
    const struct ikev2_encr_alg *encr_alg;
    const u8 *SK_e = initiator ? keys->SK_ei : keys->SK_er;
    const u8 *SK_a = initiator ? keys->SK_ai : keys->SK_ar;

    if (encrypted == NULL) {
        printf("IKEV2: No Encrypted payload in SA_AUTH");
        return NULL;
    }

    encr_alg = ikev2_get_encr(encr_id);
    if (encr_alg == NULL) {
        printf("IKEV2: Unsupported encryption type");
        return NULL;
    }
    iv_len = encr_alg->block_size;

    integ_alg = ikev2_get_integ(integ_id);
    if (integ_alg == NULL) {
        printf("IKEV2: Unsupported intergrity type");
        return NULL;
    }

    if (encrypted_len < iv_len + 1 + integ_alg->hash_len) {
        printf("IKEV2: No room for IV or Integrity Checksum");
        return NULL;
    }
    iv = encrypted;
    pos = iv + iv_len;
    end = encrypted + encrypted_len;
    integ = end - integ_alg->hash_len;

    if (SK_a == NULL) {
        printf("IKEV2: No SK_a available");
        return NULL;
    }
    if (ikev2_integ_hash(integ_id, SK_a, keys->SK_integ_len,
                 (const u8 *) hdr,
                 integ - (const u8 *) hdr, hash) < 0) {
        printf("IKEV2: Failed to calculate integrity hash");
        return NULL;
    }
    if (memcmp(integ, hash, integ_alg->hash_len) != 0) {
        printf("IKEV2: Incorrect Integrity Checksum Data");
        return NULL;
    }

    if (SK_e == NULL) {
        printf("IKEV2: No SK_e available");
        return NULL;
    }

    decrypted_len = integ - pos;
    decrypted = malloc(decrypted_len);
    if (decrypted == NULL)
        return NULL;

    if (ikev2_encr_decrypt(encr_alg->id, SK_e, keys->SK_encr_len, iv, pos,
                   decrypted, decrypted_len) < 0) {
        free(decrypted);
        return NULL;
    }
    pad_len = decrypted[decrypted_len - 1];
    if (decrypted_len < pad_len + 1) {
        printf("IKEV2: Invalid padding in encrypted payload");
        free(decrypted);
        return NULL;
    }

    decrypted_len -= pad_len + 1;

    *res_len = decrypted_len;
    return decrypted;
}


ikev2_process_sa_auth(ikeStruct *ike, ikev2_hdr *hdr) {
    unsigned char *pos;
    u8 *decrypted;
    size_t decrypted_len;
    int ret;
    struct ikev2_payloads *payloads;
    int next_payload;
    unsigned char *id, *sar2;
    unsigned char idi_len, id_type;
    u32 r_spi;

    payloads = &(ike->payloads);

    decrypted = ikev2_decrypt_payload(ike->ourProp.encr,
                      ike->ourProp.integ,
                      &ike->keys, 0, hdr, payloads->encrypted,
                      payloads->encrypted_len, &decrypted_len);
    if (decrypted == NULL)
        return -1;

    printf("\n Descryption of SA_AUTH successfull");
    ikev2ParsePayload(ike, payloads->encr_next_payload, decrypted);

    //if (ret == 0 && !ike->unknown_user) {
    if (ret == 0) {
       printf("\n Authentication iof SA_AUTH successfull");
    }
    id=(unsigned char*) payloads->idr;
    if (id == NULL) {
        printf("\n Error: No IDr recvd in Auth");
        return;
    }
    idi_len=payloads->idr_len;
    id_type = id[0];
    id = id+4; idi_len = idi_len - 4;
    if(ike->IDr)
        free(ike->IDr);
    ike->IDr = malloc(idi_len);
    if (ike->IDr == NULL) {
        printf("\n Error: no memory for IDr");
        return -1;
    }
    memcpy(ike->IDr, id, idi_len);
    ike->IDr[idi_len]='\0'; // for string operations
    ike->IDr_len = idi_len;

    // Decode SAR2
    sar2=(unsigned char*) payloads->sa;
    ike->child_r_spi= GET_BE32(sar2+8);

    free(decrypted);
    printf("\n IKE Established: i_spi: %x", ike->child_i_spi);
    //updateKernelSadSpd(ike);
    return ret;
}


int ikeSaAuthResponse (ikeStruct *ike, unsigned char *buff) {
    ikev2_hdr *ikeHdr;
    int next_payload;
    unsigned char *pos;

    // buff = ike->rBuff+28; // Jump over IP+UDP Header
    ikeHdr = (ikev2_hdr*)buff;

    // Stop the re-transmit timer that we started when we sent SA_INIT
    // stopTimer(ike);

    // Point pos to the byte after the IKE Hdr
    pos = (unsigned char*) (ikeHdr + 1);
    next_payload = ikeHdr->next_payload;
    ikev2ParsePayload(ike, next_payload, pos);
    ikev2_process_sa_auth(ike, ikeHdr);
}


unsigned char* buildTs(ikeStruct *ike, int *ts_len, int next_payload) {
    unsigned char       *ts, *tmpPtr;
    ikev2_payload_hdr   *pHdr;
    ikev2_proposal      *p;
    ikev2_transform     *t;
    ikev2_trafficSelec  *pTs;
    int                 len = 0, tlen1, tlen2;
    int                 totalLen = 0;

    ts = malloc(100);
    if (ts == NULL) {
        printf("\n Error: No mem for TS payload");
        return NULL; 
    }
    memset(ts, 0, 100);
    /*
     * Build Payload SA
     */
    pHdr = (ikev2_payload_hdr*)((char*)ts);
    pHdr->next_payload = next_payload; // IKEV2_PAYLOAD_NO_NEXT_PAYLOAD;
    pHdr->flags = 0;
    len = len + PAYLOAD_HDR_SIZE;
    
    // Put in the No. of Traffic Selectors and 3 bytes of Reserver Len
    tmpPtr = (char*)ts + len;
    tmpPtr[0] = 1;
    tmpPtr = tmpPtr + 4;
    len = len + 4;
    
    // Put in the Traffic Selector structure
    pTs = (ikev2_trafficSelec*)tmpPtr;
    pTs->type = 7; /* 7 for IPv4 */
    pTs->proto = 0;
    PUT_BE16(pTs->start_port, 0);
    PUT_BE16(pTs->end_port, 65535); // as per RFC5996, Section 3.3.1
    (pTs->startIP, inet_addr("0.0.0.0"));
    (pTs->endIP, inet_addr("0.0.0.0"));
    PUT_BE16(pTs->ts_length, 16);

    len = len + 16;

    PUT_BE16(pHdr->payload_length, len);

    *ts_len = len;
    return ts;
}   

int ikev2_derive_auth_data(int prf_alg, void *sign_msg,
               const u8 *ID, size_t ID_len, u8 ID_type,
               struct ikev2_keys *keys, int initiator,
               const u8 *shared_secret, size_t shared_secret_len,
               const u8 *nonce, size_t nonce_len,
               const u8 *key_pad, size_t key_pad_len,
               u8 *auth_data, ikeStruct *ike)
{
    size_t sign_len, buf_len;
    u8 *sign_data, *pos, *buf, hash[IKEV2_MAX_HASH_LEN];
    const struct ikev2_prf_alg *prf;
    const u8 *SK_p = initiator ? keys->SK_pi : keys->SK_pr;

    prf = ikev2_get_prf(prf_alg);
    if (sign_msg == NULL || ID == NULL || SK_p == NULL ||
        shared_secret == NULL || nonce == NULL || prf == NULL)
        return -1;

    /* prf(SK_pi/r,IDi/r') */
    buf_len = 4 + ID_len;
    buf = malloc(buf_len);
    if (buf == NULL)
        return -1;
    memset(buf, 0, buf_len);
    buf[0] = ID_type;
    memcpy(buf + 4, ID, ID_len);
    if (ikev2_prf_hash(prf->id, SK_p, keys->SK_prf_len,
               1, (const u8 **) &buf, &buf_len, hash) < 0) {
        free(buf);
        return -1;
    }
    free(buf);

    /* sign_data = msg | Nr/i | prf(SK_pi/r,IDi/r') */
    sign_len = ike->saInitLen + nonce_len + prf->hash_len;
    sign_data = malloc(sign_len);
    if (sign_data == NULL)
        return -1;
    pos = sign_data;
    memcpy(pos, ike->saInitBuff, ike->saInitLen);
    pos += ike->saInitLen;
    memcpy(pos, nonce, nonce_len);
    pos += nonce_len;
    memcpy(pos, hash, prf->hash_len);

    /* AUTH = prf(prf(Shared Secret, key pad), sign_data) */
    if (ikev2_prf_hash(prf->id, shared_secret, shared_secret_len, 1,
               &key_pad, &key_pad_len, hash) < 0 ||
        ikev2_prf_hash(prf->id, hash, prf->hash_len, 1,
               (const u8 **) &sign_data, &sign_len, auth_data) < 0)
    {
        free(sign_data);
        return -1;
    }
    free(sign_data);

    return 0;
}

unsigned char* buildSai2(ikeStruct *ike, int *sai_len, int next_payload) {
    unsigned char       *sai2, *tmpPtr;
    ikev2_payload_hdr   *pHdr;
    ikev2_proposal      *p;
    ikev2_transform     *t;
    int                 len = 0, tlen1, tlen2;
    int                 totalLen = 0;

    sai2 = malloc(200);
    if (sai2 == NULL) {
        printf("\n Error: No mem for SAi2 payload");
        return NULL;
    }
    /*
     * Build Payload SA
     */
    pHdr = (ikev2_payload_hdr*)((char*)sai2);
    pHdr->next_payload = next_payload; // IKEV2_PAYLOAD_TS;
    pHdr->flags = 0;
    len = len + PAYLOAD_HDR_SIZE;

    // Put the Proposal
    p = (ikev2_proposal*)((char*) sai2+len);
    p->type = 0; // last proposal
    p->reserved = 0;
    p->protocol_id = IKEV2_PROTOCOL_ESP; // IKEV2_PROTOCOL_ESP
    p->proposal_num = 1;
    p->spi_size = 4;
    p->num_transforms = 3;  // ESP has 4 transforms- Encryp, Auth, 2 ESN
    len = len + PROPOSAL_LEN;

    // SAI 4 Byte Data
    tmpPtr = ((char*)sai2 + len);
    memset(tmpPtr, 4, 0);
    PUT_BE32(tmpPtr, ike->child_i_spi); //verifiedwith Strongswan
    // printf("\nchild i_spi =%x", ike->child_i_spi);
    len = len + 4;

// Repeat for each of the 4 transforms for ESP Proposal (Encr, Auth and 2 ESN)
// Next Transform - Encryption
    t = (ikev2_transform*)((char*)sai2 + len);
    // 3 indicates more transfors to come. 0 indicates last transform.
    t->type = 3;
    t->reserved= 0;
    t->transform_type = IKEV2_TRANSFORM_ENCR;
    PUT_BE16(t->transform_id, ike->ourProp.encr); // TODO: take as a param
    tmpPtr = (char*)sai2 + len + TRANSFORM_SIZE;
        /* Transform Attribute: Key Len = 128 bits */
        PUT_BE16(tmpPtr, 0x800e); /* AF=1, AttrType=14 */
        tmpPtr += 2;
        PUT_BE16(tmpPtr, 128); /* 128-bit key */
    PUT_BE16(t->transform_length, TRANSFORM_SIZE + AES_PARAM_SIZE);
    // We save each transform len in tlen variables
    tlen1 = TRANSFORM_SIZE + AES_PARAM_SIZE;
    len = len + tlen1;

// Next Transform - Authentication
    t = (ikev2_transform*)((char*)sai2 + len);
    t->type = 3;
    t->reserved= 0;
    t->transform_type = IKEV2_TRANSFORM_INTEG;
    PUT_BE16(t->transform_id, AUTH_HMAC_SHA1_96);
    PUT_BE16(t->transform_length, TRANSFORM_SIZE);
    tlen2 = TRANSFORM_SIZE;
    len = len + tlen2;


// Next Transform - Extended Sequence Number
    t = (ikev2_transform*)((char*)sai2 + len);
    t->type = 0;
#define NO_EXTENDED_SEQ_NUMBER 0
    t->reserved= 0;
    t->transform_type = IKEV2_TRANSFORM_ESN;
    PUT_BE16(t->transform_id, NO_EXTENDED_SEQ_NUMBER);
    PUT_BE16(t->transform_length, TRANSFORM_SIZE);
    tlen2 = TRANSFORM_SIZE;
    len = len + tlen2;

// Next Transform
/*
    t = (ikev2_transform*)((char*)sai2 + len);
    t->type = 0;
#define EXTENDED_SEQ_NUMBER 1
    t->reserved= 0;
    t->transform_type = IKEV2_TRANSFORM_ESN;
    PUT_BE16(t->transform_id, EXTENDED_SEQ_NUMBER);
    PUT_BE16(t->transform_length, TRANSFORM_SIZE);
    len = len + TRANSFORM_SIZE;
*/
    PUT_BE16(p->proposal_length, len - PAYLOAD_HDR_SIZE);
    PUT_BE16(pHdr->payload_length, len);
    printf("\n Security Payload Len = %d", len);

    *sai_len = len;
    return sai2;
}

int sendAuth (ikeStruct *ike) {
    unsigned char *msg, *plain, *ts;
    const u8 *secret;
    size_t secret_len;
    const struct ikev2_prf_alg *prf;
    unsigned char *sai2;
    int sai_len, ts_len;

    int message_id = 1;  /* INIT uses 0, AUTH uses 1 */
    int len = 0, plen = 0;
    char *tmpPtr;
    int totalLen;

    secret_len = ike->user_password_len;
    secret     = ike->user_password;
    ike->shared_secret = ike->user_password;
    ike->shared_secret_len = ike->user_password_len;

    // Various hdrs as we build them
    ikev2_hdr *hdr;
    ikev2_payload_hdr *pHdr;

    printf("\n Start of IKE Auth Session");
    msg = getBuff(sizeof(ikev2_hdr) + IKE_PKT_SIZE);
    if (msg == NULL) {
        printf("\nNo Memory in sendAuth:");
        return -1;
    }
    hdr = (ikev2_hdr*)msg;
    /*
     * Build IKE Hdr
     */
    memcpy(hdr->i_spi, ike->i_spi, IKEV2_SPI_LEN);
    memcpy(hdr->r_spi, ike->r_spi, IKEV2_SPI_LEN);
    hdr->next_payload = IKEV2_PAYLOAD_ENCRYPTED;
    hdr->version = IKEV2_VERSION; /* MjVer | MnVer */
    hdr->exchange_type = IKE_SA_AUTH;
    hdr->flags = IKEV2_HDR_INITIATOR;
    PUT_BE32(hdr->message_id, message_id);  // 1 for SA_AUTH
    len = len+sizeof(ikev2_hdr);

    /* build IKE_SA_AUTH: HDR, SK {IDi, [CERT,] [CERTREQ,] AUTH} */
    plain = malloc(IKE_PKT_SIZE);
    if (plain == NULL) {
        printf("\nNo Memory in ikeStart for plain pkt:");
        return;
    }

    /*
     * Build payload IDi
     */
    pHdr = (ikev2_payload_hdr*)((char*)plain);
    pHdr->next_payload = IKEV2_PAYLOAD_AUTHENTICATION;
    pHdr->flags = 0;
    plen = PAYLOAD_HDR_SIZE;
    tmpPtr = (char*)plain + plen;
    *tmpPtr=ID_KEY_ID;
    tmpPtr+=1;
    memset(tmpPtr, 0, 3);
    tmpPtr+=3;
    memcpy(tmpPtr, ike->IDi, ike->IDi_len);
    plen = plen + 4 + ike->IDi_len;
    PUT_BE16(pHdr->payload_length, (4+ike->IDi_len+PAYLOAD_HDR_SIZE));

    /*
     * Build payload Auth
     */
    pHdr = (ikev2_payload_hdr*)((char*)plain+plen);
    pHdr->next_payload = IKEV2_PAYLOAD_SA;
    //      IKEV2_PAYLOAD_NO_NEXT_PAYLOAD;
    pHdr->flags = 0;
    plen += PAYLOAD_HDR_SIZE;
    prf = ikev2_get_prf(ike->ourProp.prf);
    if (prf == NULL)
        return -1;
    tmpPtr = (char*)plain + plen;
    *tmpPtr=AUTH_SHARED_KEY_MIC;
    tmpPtr+=1;
    memset(tmpPtr, 0, 3);
    tmpPtr+=3;

    /* msg | Nr | prf(SK_pi,IDi') */
    if (ikev2_derive_auth_data(ike->ourProp.prf, ike->saInitBuff,
                   ike->IDi, ike->IDi_len, ID_KEY_ID,
                   &ike->keys, 1, ike->shared_secret,
                   ike->shared_secret_len,
                   ike->r_nonce, ike->r_nonce_len,
                   ike->key_pad, ike->key_pad_len,
                   tmpPtr, ike) < 0) {
        printf("IKEV2: Could not derive AUTH data");
        return -1;
    }
    plen = plen + 4 + prf->hash_len;
    PUT_BE16(pHdr->payload_length, (4+prf->hash_len+PAYLOAD_HDR_SIZE));

    // Build the SAi2 payload and update plen of the plain packet
    sai2 = buildSai2(ike, &sai_len, IKEV2_PAYLOAD_TSi);
    if (sai2 == NULL)
        return -1;
    memcpy(plain+plen, sai2, sai_len);
    plen = plen + sai_len;

    // Build the TSi payload and update plen of the plain packet
    ts = buildTs(ike, &ts_len, IKEV2_PAYLOAD_TSr);
    if (ts == NULL)
        return -1;
    memcpy(plain+plen, ts, ts_len);
    plen = plen + ts_len;

    ts_len = 0;
    free(ts);

    // Build the TSr payload and update plen of the plain packet
    ts = buildTs(ike, &ts_len, IKEV2_PAYLOAD_NO_NEXT_PAYLOAD);
    if (ts == NULL)
        return -1;
    memcpy(plain+plen, ts, ts_len);
    plen = plen + ts_len;

    ikev2_build_encrypted(ike->ourProp.encr, ike->ourProp.integ,
                          &ike->keys, 1, &msg[len], plain,
                          IKEV2_PAYLOAD_IDi, len, msg, plen);
    free(sai2);
    free(ts);
    free(plain);

    // Put the total length
    len = GET_BE32(hdr->length);
    if (len == 0) return -1;
    printf("\n Total Len of IKE_AUTH = %d", len);
    sendData(ike, msg, len);
}


int ikev2_process_sar1(ikeStruct *ike) {
    unsigned char   *pos, *end;
    unsigned char   *ppos, *pend;
    unsigned char   *tpos, *tend;
    struct  ikev2_proposal *p;
    int     proposal_len, transform_id;
    int     i;

    // Get the Proposal Details
    ike->prop.proposal_num = 1; // we do one proposal for now
    pos = ike->payloads.sa;
    end = pos + ike->payloads.sa_len;
    p = (ikev2_proposal *) pos;
    if (p == 0) {
        printf("\n No SA payload");
        return -1;
    }
    proposal_len = GET_BE16(p->proposal_length);

    // Proposal Data Details
    ppos = (unsigned char*) (p + 1);
    pend = pos + proposal_len;
    if (p->spi_size) {
        ppos += p->spi_size;
        printf("IKEV2:    SPI Size = %d", p->spi_size);
    }

    for (i = 0; i < (int) p->num_transforms; i++) {
        const struct ikev2_transform *t;
        int tlen;
        t = (const struct ikev2_transform *)ppos;
        tlen = GET_BE16(t->transform_length);
        if (tlen < 0)
                return -1;
        tend = ppos + tlen;
        transform_id = GET_BE16(t->transform_id);
        ppos = (char *) (t + 1);
        switch (t->transform_type) {
        case IKEV2_TRANSFORM_ENCR:
        printf("\n IKEV2_TRANSFORM_ENCR found");
        if (ikev2_get_encr(transform_id) &&
            transform_id == ike->ourProp.encr) {
            if (transform_id == ENCR_AES_CBC) {
                int j;
                printf("\n   AES attributes: ");
                //for (j=0;j<4;j++)
                //  printf("%02x ", (unsigned char)ppos[j]);
                printf("Transform id = ENCR_AES_CBC");
                if (tend - ppos != 4) {
                   printf("\nIKEV2: No Transform Attr for AES"); break;
                }
                if (GET_BE16(ppos) != 0x800e) {
                    printf("\nIKEV2: Not Key Size attribute for AES"); break;
                }
                if (GET_BE16(ppos+2) != 128) {
                    printf("\nIKEV2: Unsupported AES key size %d bits",
                               GET_BE16(ppos+2));
                    break;
                }
            }
            ike->prop.encr = transform_id;
        }
        break;
        case IKEV2_TRANSFORM_PRF:
        if (ikev2_get_prf(transform_id) &&
            transform_id == ike->ourProp.prf) {
            ike->prop.prf = transform_id;
            printf("\n IKEV2_TRANSFORM_PRF found");
        }
        break;
        case IKEV2_TRANSFORM_INTEG:
        if (ikev2_get_integ(transform_id) &&
            transform_id == ike->ourProp.integ) {
            ike->prop.integ = transform_id;
            printf("\n IKEV2_TRANSFORM_INTEG found");
        }
        break;
        case IKEV2_TRANSFORM_DH:
        if (dh_groups_get(transform_id) &&
            transform_id == ike->ourProp.dh) {
            ike->prop.dh = transform_id;
            printf("\n IKEV2_TRANSFORM_DH found");
        }
        break;
        }
        ppos = ppos + tlen - sizeof(ikev2_transform);
    }
    return 0;
}

/*
 * Key Exchange Payload:
 * DH Group # (16 bits)
 * RESERVED (16 bits)
 * Key Exchange Data (Diffie-Hellman public value)
 */
int ikev2_process_ker(ikeStruct *ike) {
    unsigned char *ker;
    unsigned char ker_len;
    unsigned short group;

    ker = ike->payloads.ke;
    ker_len = ike->payloads.ke_len;

    if (ker == NULL) {
        printf("IKEV2: KEr not received");
        return -1;
    }

    if (ker_len < 4 + 96) {
        printf("IKEV2: Too small Key Exchange Payload");
        return -1;
    }

    group = GET_BE16(ker);
    printf("\nIKEV2: KEr DH Group #%u", group);

    if (group != ike->ourProp.dh) {
        printf("IKEV2: KEr DH Group #%u does not match "
               "with the selected proposal (%u)",
               group, ike->ourProp.dh);
        return -1;
    }

    ike->r_dh_public = malloc(ker_len - 4);
    memcpy(ike->r_dh_public, ker+4, ker_len-4);
    ike->r_dh_public_len = ker_len -4;
    if (ike->r_dh_public == NULL)
        return -1;

    return 0;
}

int ikev2_process_nr(ikeStruct *ike) {
    unsigned char *nr;
    unsigned char nr_len;

    nr = ike->payloads.nonce;
    nr_len = ike->payloads.nonce_len;
    if(nr == NULL) {
        printf("\n No Nonce found");
        return -1;
    }

    ike->r_nonce_len = nr_len;
    ike->r_nonce = malloc(nr_len);
    memcpy(ike->r_nonce, nr, nr_len);
        printf("\nIKEV2: Nonce Len:%d", nr_len);
        hexdump(ike->r_nonce, nr_len);
    return 0;
}

/* Maximum hash length for supported hash algorithms */
#define IKEV2_MAX_HASH_LEN 20
int ikev2_derive_keys(ikeStruct *ike) {
    const struct    ikev2_integ_alg *integ;
    const struct    ikev2_prf_alg *prf;
    const struct    ikev2_encr_alg *encr;
    unsigned char   *buf, *pos, *pad;
    unsigned int    buf_len, pad_len;
    int             ret;
    const u8        *addr[2];
    size_t          len[2];
    unsigned char   skeyseed[IKEV2_MAX_HASH_LEN];
    size_t          shared_len, malloc_pad_len;

    integ = ikev2_get_integ(ike->ourProp.integ);
    prf = ikev2_get_prf(ike->ourProp.prf);
    encr = ikev2_get_encr(ike->ourProp.encr);
    if (integ == NULL || prf == NULL || encr == NULL) {
        printf("IKEV2: Unsupported proposal");
        return -1;
    }
    ike->shared = dh_derive_shared(ike->r_dh_public, ike->i_dh_private,
                              ike->dh, &shared_len, ike->r_dh_public_len);
    ike->shared_len = shared_len;
    if (ike->shared == NULL)
        return -1;
    printf("\n Shared Key Derived");

    /* Section 2.15 - Generating Keys */

    /* Construct Ni | Nr | SPIi | SPIr */
    buf_len = ike->i_nonce_len + ike->r_nonce_len + 2 * IKEV2_SPI_LEN;
    buf = malloc(buf_len);
    if (buf == NULL) {
        free(ike->shared); return -1;
    }
    pos = buf;
    memcpy(pos, ike->i_nonce, ike->i_nonce_len);
    pos += ike->i_nonce_len;
    memcpy(pos, ike->r_nonce, ike->r_nonce_len);
    pos += ike->r_nonce_len;
    memcpy(pos, ike->i_spi, IKEV2_SPI_LEN);
    pos += IKEV2_SPI_LEN;
    memcpy(pos, ike->r_spi, IKEV2_SPI_LEN);

    /* SKEYSEED = prf(Ni | Nr, g^ir) */

    /* Use zero-padding per RFC 4306, Sect. 2.14 */
    pad_len = ike->dh->prime_len - shared_len;
    if (pad_len == 0) malloc_pad_len = 1;
    printf("\n PAD len = %d", pad_len);
    pad = malloc(malloc_pad_len);
    if (pad == NULL) {
        free(ike->shared); free(buf); return -1;
    }
    memset(pad, 0, malloc_pad_len);

    addr[0] = pad;
    len[0] = pad_len;
    addr[1] = ike->shared;
    len[1] = ike->shared_len;
    if (ikev2_prf_hash(prf->id, buf, ike->i_nonce_len + ike->r_nonce_len,
               2, addr, len, skeyseed) < 0) {
        free(ike->shared);
        free(buf);
        free(pad);
        return -1;
    }
    printf("\n PRF Hash success");
        printf("\nIKEV2: SKEYSEED %d:", prf->hash_len);
        hexdump(skeyseed, prf->hash_len);

    free(pad);
    free(ike->shared);
    /* DH parameters are not needed anymore, so free them */
    free(ike->r_dh_public);
    ike->r_dh_public = NULL;
    free(ike->i_dh_private);
    ike->i_dh_private = NULL;


    ret = ikev2_derive_sk_keys(prf, integ, encr, skeyseed, buf, buf_len,
                   &ike->keys);
    free(buf);
    return ret;

    return 0;
}

/*
 * Code reused from wpa_supplicant/src/eap_common/ikev2_common.c
 */
ikev2ParsePayload(ikeStruct *ike, int next_payload, char *pos) {
    struct ikev2_payloads *payloads;
    ikev2_payload_hdr *pHdr;
    char *pData;
    int pLen, pDataLen;

    payloads = &(ike->payloads);
    memset(payloads, 0, sizeof(*payloads));

    while (next_payload != IKEV2_PAYLOAD_NO_NEXT_PAYLOAD) {
        pHdr = (ikev2_payload_hdr*)pos;
        pLen = GET_BE16(pHdr->payload_length);
        pData = (unsigned char*) (pHdr + 1);
        pDataLen = pLen - sizeof(*pHdr);

        switch (next_payload) {
        case IKEV2_PAYLOAD_SA:
            printf("\nIKEV2:   Payload: Security Association");
            payloads->sa = pData;
            payloads->sa_len = pDataLen;
            break;
        case IKEV2_PAYLOAD_KEY_EXCHANGE:
                printf("\nIKEV2:   Payload: Key Exchange");
            payloads->ke = pData;
            payloads->ke_len = pDataLen;
            break;
        case IKEV2_PAYLOAD_IDi:
                printf("\nIKEV2:   Payload: IDi");
            payloads->idi = pData;
            payloads->idi_len = pDataLen;
            break;
        case IKEV2_PAYLOAD_IDr:
                printf("\nIKEV2:   Payload: IDr");
            payloads->idr = pData;
            payloads->idr_len = pDataLen;
            break;
        case IKEV2_PAYLOAD_CERTIFICATE:
                printf("\nIKEV2:   Payload: Certificate");
            payloads->cert = pData;
            payloads->cert_len = pDataLen;
            break;
        case IKEV2_PAYLOAD_AUTHENTICATION:
                printf("\nIKEV2:   Payload: Authentication");
            payloads->auth = pData;
            payloads->auth_len = pDataLen;
            fflush(stdout);
            break;
        case IKEV2_PAYLOAD_NONCE:
                printf("\nIKEV2:   Payload: Nonce");
            payloads->nonce = pData;
            payloads->nonce_len = pDataLen;
            break;
        case IKEV2_PAYLOAD_ENCRYPTED:
                printf("\nIKEV2:   Payload: Encrypted");
            payloads->encrypted = pData;
            payloads->encrypted_len = pDataLen;
            break;
        case IKEV2_PAYLOAD_NOTIFICATION:
                printf("\nIKEV2:   Payload: Notification");
            payloads->notification = pData;
            payloads->notification_len = pDataLen;
                printf(", Type = %d: %s", GET_BE16(pData+2),
                            payloadToString(GET_BE16(pData+2)));
                if(GET_BE16(pData+2) < 44)
                        printf("...Error ! - TS_UNACCEPTABLE");
            if(GET_BE16(pData+2) == REDIRECT_PAYLOAD) {
                payloads->redirect = pData;
                payloads->redirect_len = pDataLen;
            }
            break;
        default:
            if (pHdr->flags & IKEV2_PAYLOAD_FLAGS_CRITICAL) {
                printf("IKEV2: Unsupported critical payload %u - reject the "
                       "entire message", next_payload);
                return -1;
            } else {
                printf("\nIKEV2:   Skipped unsupported payload %u:%s",
                       next_payload, payloadToString(next_payload));
            }
        }

//      if (next_payload == IKEV2_PAYLOAD_ENCRYPTED &&
//          pLen == ike->rLen) {
        //  Changed to following, since Encrypted payloads are last anyways
        if (next_payload == IKEV2_PAYLOAD_ENCRYPTED) {
            /*
             * Next Payload in the case of Encrypted Payload is
             * actually the payload type for the first embedded
             * payload.
             */
            payloads->encr_next_payload = pHdr->next_payload;
            next_payload = IKEV2_PAYLOAD_NO_NEXT_PAYLOAD;
        } else
            next_payload = pHdr->next_payload;

        pos += pLen;
    }
}



/*
 Recv IKE_INIT_SA Response
 HDR, SAr1, KEr, Nr, [CERTREQ]

 HDR: includes initiator’s Security Parameter Index, the responder’s Security Parameter Index, IKE version, flags, and the same message identifier as was used in the IKE_SA_INIT request.
 The responder agrees to a proposal for the cryptographic algorithms and identifies this in the SAr1 payload.
 KEr: includes the responder’s Diffie-Hellman value.
 Nr: contains the responder’s nonce.

 Following table identifies the typical size of an IKE_SA_INIT response message.

 Payload       		        Size (octets)
 HDR (fixed size)       	28
 SAr1 (1 prop, 4 transf)	48
 KEr                		8 + a (size of Diffie-Hellman group)
 Nr             		4 + b (size of nonce chosen by initiator)
 Total  88 + a + b
*/
int ikeSaInitResponse (ikeStruct *ike, unsigned char *buff) {
    ikev2_hdr *ikeHdr;
    int next_payload;
    unsigned char *pos;
    int ret = 0;
    static int first = 0;

    // buff = ike->rBuff+28; // Jump over IP+UDP Header
    ikeHdr = (ikev2_hdr*)buff;

    // Point pos to the byte after the IKE Hdr
    pos = (unsigned char*) (ikeHdr + 1);
    next_payload = ikeHdr->next_payload;
    ikev2ParsePayload(ike, next_payload, pos);
    // ike->payloads struct is all filled in now with the pointers
    // sa, ke and nonce
    memcpy(ike->r_spi, ikeHdr->r_spi, IKEV2_SPI_LEN);
    if (ikev2_process_sar1(ike) < 0 || ikev2_process_ker(ike) < 0 ||
        ikev2_process_nr(ike) < 0)
                        return -1;
    if (ikev2_derive_keys(ike) < 0)
        return -1;
    sendAuth(ike);
}

int dataEvent (ikeStruct *ike, int ikeEvent, unsigned char *buff) {
    ikev2_hdr *ikeHdr;
    int message_id, length;

//  buff = (unsigned char*)ike->rBuff+28; // Jump over IP+UDP Header
    ikeHdr = (ikev2_hdr*)buff;
    message_id = GET_BE32(ikeHdr->message_id);
    length = GET_BE32(ikeHdr->length);
    if (ikeHdr->version != IKEV2_VERSION) {
        printf("\n IKEV2: Unsupported HDR version 0x%x "
               "(expected 0x%x)", ikeHdr->version, IKEV2_VERSION);
        return -1;
    }

    if ((ikeHdr->flags & (IKEV2_HDR_INITIATOR | IKEV2_HDR_RESPONSE)) !=
        IKEV2_HDR_RESPONSE) {
        // This is fine, since Notification Pkts come with flag 0x0
        printf("\n IKEV2: Unexpected Flags value 0x%x", ikeHdr->flags);
    }
    switch(ike->curState) {
    case IKE_START_STATE:
        break;
    case IKE_INIT_STATE:
        if (ikeHdr->exchange_type == IKE_SA_INIT)
            printf("\n Data Event: IKE_SA_INIT recvd");
        ikeSaInitResponse(ike, buff);
        break;
    case IKE_AUTH_STATE:
        if (ikeHdr->exchange_type == IKE_SA_AUTH) {
            printf("\n Data Event: IKE_SA_AUTH recvd");
            ikeSaAuthResponse(ike, buff);
        } else {
            if (ikeHdr->exchange_type == INFORMATION) {
                printf("\n Data Event: Notification:..Ignore");
            } else {
                printf("\n Data Event: Other Data: %d ..Ignore",
			ikeHdr->exchange_type);
            }
        }
        break;
    case IKE_ESTAB_STATE:
        printf("\nData recvd: %d", ikeHdr->exchange_type);
        break;
    }
    fflush(stdout);
    free(buff);  // FSM buffer
    return 1;
}



// FSM
typedef struct {
	int (*funcPtr)(ikeStruct *ike, int ikeEvent, unsigned char* fsmBuff);
	int nextState;
} fsmStruct;

int InvalidEvent (ikeStruct *ike, int ikeEvent, unsigned char *buff) {
	if (buff != NULL)
		free(buff);
	return 1;
}
int timeoutEvent (ikeStruct *ike, int ikeEvent, unsigned char *buff) {
	if (buff != NULL)
		free(buff);
	return 1;
}

static fsmStruct ikeFsm[4][4] = {
	{ /* IKE_START */
		{ikeStart, IKE_INIT_STATE}, //INIT_EVENT
		{InvalidEvent, NO_CHANGE},  //TIMEOUT_EVENT
		{InvalidEvent, NO_CHANGE},  //DATA_EVENT
		{InvalidEvent, NO_CHANGE}   //REDIRECT_EVENT
	},
	{ /* IKE_INIT */
		{InvalidEvent, NO_CHANGE},
		{timeoutEvent, NO_CHANGE},
		{dataEvent, IKE_AUTH_STATE},
		{InvalidEvent, NO_CHANGE}
	},
	{ /* IKE_AUTH */
		{InvalidEvent, NO_CHANGE},
		{InvalidEvent, NO_CHANGE},
		{dataEvent, IKE_ESTAB_STATE},
		{ikeStart, IKE_INIT_STATE}
	},
	{ /* IKE_ESTAB */
		{InvalidEvent, NO_CHANGE},
		{InvalidEvent, NO_CHANGE},
		{dataEvent, NO_CHANGE},
		{InvalidEvent, NO_CHANGE}
	}
};

fsmRoutine() {
        ikeStruct *ike;
        fsmParam *fp;
        unsigned char *fsmBuff;
        int event;
        int count = 0;

        printf("\n.................................IKE FSM starting ");
        while (1) {
        // "do" is done here, since when Q is full, QHead = QTail
        do {
            if (ikeFsmQ[ikeFsmQHead] != 0) {
					printf("\n Recv event in FSM thread.."); fflush(stdout);
                    fp = ikeFsmQ[ikeFsmQHead];
                    ike = fp->ike;
                    fsmBuff = fp->fsmBuff;
                    event = fp->ikeEvent;
                    ikeFsm[ike->curState][event].funcPtr(ike, event, fsmBuff);
                    if (ikeFsm[ike->curState][event].nextState != NO_CHANGE)
                            ike->curState =
                                    ikeFsm[ike->curState][event].nextState;
                    free(ikeFsmQ[ikeFsmQHead]);
                    ikeFsmQ[ikeFsmQHead] = 0;
                    if (ikeFsmQHead == FSM_Q_SIZE-1) {
                            printf("ikeFsmQHead wraps to 0\n");
                            ikeFsmQHead = 0;
                    } else
                            ikeFsmQHead++;
                    if ((++count % 50) == 0) {
                            printf("...FSM routine sleeping\n");
                            sleep(3);
                    }
            } else {
            // stay at this same ikeFsmQHead point and 
            // keep checking every second.
                    sleep(1);
                    continue;
            }
        } while(ikeFsmQHead != ikeFsmQTail);
            sleep(1);
        }
}

ikeFsmExecute (ikeStruct *ike, int ikeEvent, unsigned char *fsmBuff)
{
    fsmParam  *fp;
    char      status;

    printf("\nIKE_FSM: Cur State: %s, Event: %s",
            stateToString(ike->curState), eventToString(ikeEvent));

    fp = (fsmParam*)malloc(sizeof(fsmParam));
    if (fp == 0) {
        printf("\n No mem at ikeFsmExecute");
        return;
    }
    fp->ikeEvent = ikeEvent;
    fp->ike = ike;
    fp->fsmBuff = fsmBuff;

    if (ikeFsmQ[ikeFsmQTail] == 0) {
		printf("\n FSMQTail was 0");
        ikeFsmQ[ikeFsmQTail] = fp;
        if (ikeFsmQTail == FSM_Q_SIZE-1) {
            printf("ikeFsmQTail wraps to 0\n");
            ikeFsmQTail = 0;
        } else
            ikeFsmQTail++;
    } else {
        printf("FSM event dropped...Q full\n");
    }
}


main() {
	int status;
	pthread_t fsmThread;

	printf("\n IPSec sim started..");
	strcpy(cfg.utIP, "192.168.1.22");
    status = pthread_create(&fsmThread, NULL, &fsmRoutine, (void*)NULL);
    if (status != 0) {
    	perror("FSM Thread Error:"); return -1;
	}
	getSelfIpAddress();
	initDataSocket();
	printf("\n");
    ikeFsmExecute(&(cfg.ike), INIT_EVENT, NULL);
	recvPackets();
	return 1;
}
