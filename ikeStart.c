#include "sim.h"

extern ipsecCfg cfg;
extern int global_pv_len;

hexdump(unsigned char* buf, int len) {
    int i;
    for (i = 0; i < len; i++)
        printf(" %02x", buf[i]);
}

initVars() {
    char ID[10] = "IkeSim";
    char i_str[IKEV2_SPI_LEN];
    int identity_len = 4;

    cfg.ike.ourProp.integ = AUTH_HMAC_SHA1_96;
    cfg.ike.ourProp.prf = PRF_HMAC_SHA1;
    cfg.ike.ourProp.encr = ENCR_AES_CBC;
    cfg.ike.ourProp.dh = DH_GROUP1_768BIT_MODP;
// DH_GROUP5_1536BIT_MODP;
    cfg.ike.redirected = FALSE;

    cfg.ike.key_pad = (u8 *)strdup("Key Pad for IKEv2");
    if (cfg.ike.key_pad == NULL) {
        printf("\nkey_pad malloc failed");
        return -1;
    }
    cfg.ike.key_pad_len = 17;

    memset(cfg.ike.i_spi, 0, IKEV2_SPI_LEN);
    //sprintf(i_str, "%d", 1);
    //memcpy(cfg.ike.i_spi, i_str, strlen(i_str));
	cfg.ike.i_spi[0] = 1;
    //printf(", i_spi = %s", cfg.ike.i_spi);
    cfg.ike.srcPort = 4000;
    cfg.ike.child_i_spi = 100000;

    cfg.ike.IDi = strdup(strcat(ID, i_str));
    strcpy(ID, "IkeSim"); // reset ID back to IkeSim
    cfg.ike.IDi_len = strlen(cfg.ike.IDi);
    
    // Default identity for Other Server
    cfg.ike.IDr = malloc(identity_len);
    if (cfg.ike.IDr == NULL) {
        perror("\n Cannot allocate IDr");
    }
    memcpy(cfg.ike.IDr, "Strong", identity_len);
    cfg.ike.IDr_len = identity_len;
    cfg.ike.IDr[cfg.ike.IDr_len] = '\0'; // for string operations

    memcpy(cfg.ike.user_password, "password", 8);
    cfg.ike.user_password_len = 8;
}

// This takes care of the IP + UDP Hdr we are adding later
void* getBuff(int size) {
    unsigned char *buff;
    buff = malloc(size+IPV4_UDP_SIZE);
    if (buff == NULL)
        return NULL;
    return buff+IPV4_UDP_SIZE;
}

/*
 Start process of creating IKE_SA: send IKE_SA_INIT
 HDR, SAi1, KEi, Ni

 HDR: Security Parameter Index, IKE version, flags, message id 
 	used for retransmissions and matching responses to requests.
 SAi1: includes crypto algorithms for IKE_SA. 
 	Proposal for encryption, pseudorandom function, integrity, and 
 	Diffie-Hellman group.
 KEi: payload includes the initiator’s Diffie-Hellman value.
 Ni: payload contains initiator’s nonce, used to protect against 
 	replay attacks.
 
 Following table identifies typical size of an IKE_SA_INIT request message.
 Payload				Size (octets)
 HDR (fixed size)		28
 SAi1 (1 proposal, 4 transforms)	48
 KEi				8 + a (size of the Diffie-Hellman group)
 Ni				4 + b (size of the nonce chosen by initiator)
 Total				88 + a + b
*/
int ikeStart (ikeStruct *ike, int ikeEvent, unsigned char *junk) {
	void *buff;
	int message_id = 0;  /* INIT uses 0, AUTH uses 1 */
	int len = 0;
	char *tmpPtr;
	int totalLen;
	int tlen1, tlen2, tlen3, tlen4;
	int dHKeyLen = 0;
	int dhLen;
	void *dhPublic;


	initVars();
	// Various hdrs as we build them
	ikev2_hdr *hdr;
	ikev2_payload_hdr *pHdr;
	ikev2_proposal *p;
	ikev2_transform *t;

	buff = getBuff(sizeof(ikev2_hdr) + IKE_PKT_SIZE);
	if (buff == NULL) {
		printf("\nNo Memory in ikeStart:");
		return;
	}
	hdr = (ikev2_hdr*)buff;
	/*
	 * Build IKE Hdr
	 */
    // IKE_SA Initiator's SPI
	memcpy(hdr->i_spi, ike->i_spi, IKEV2_SPI_LEN);
	// IKE_SA Responder's SPI
	memset(hdr->r_spi, 0, IKEV2_SPI_LEN);
	hdr->next_payload = IKEV2_PAYLOAD_SA;
	hdr->version = IKEV2_VERSION; /* MjVer | MnVer */
	hdr->exchange_type = IKE_SA_INIT;
	hdr->flags = IKEV2_HDR_INITIATOR;
	/*
	The Message ID is a 32-bit quantity, which is zero for the
	IKE_SA_INIT messages (including retries of the message due to
	responses such as COOKIE and INVALID_KE_PAYLOAD), and incremented for
	each subsequent exchange.  Thus, the first pair of IKE_AUTH messages
	will have an ID of 1
	 */
	PUT_BE32(hdr->message_id, message_id);  // 0 for SA_INIT
	len = len+sizeof(ikev2_hdr);
	/*
	 * Build Payload SA
	 */
	pHdr = (ikev2_payload_hdr*)((char*) buff+len);
	pHdr->next_payload = IKEV2_PAYLOAD_KEY_EXCHANGE;
	pHdr->flags = 0;
	len = len + PAYLOAD_HDR_SIZE;

	/* Proposal structure - RFC 5996
                        1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | 0 (last) or 2 |   RESERVED    |         Proposal Length       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Proposal Num  |  Protocol ID  |    SPI Size   |Num  Transforms|
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ~                        SPI (variable)                         ~
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                        <Transforms>                           ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   	*/
	// Put the Proposal
	p = (ikev2_proposal*)((char*) buff+len);
	p->type = 0; // last proposal
	p->reserved = 0;
	// In ikev1, we had ESP, AH and IKE. In IKEv2, only IKE is allowed.
	p->protocol_id = IKEV2_PROTOCOL_IKE;
	p->proposal_num = 1;
	p->spi_size = 0;
	p->num_transforms = 4;  // IKE has 4 transforms
	// Diffie-Hellman group, 
	// integrity check algo, 
	// PRF algo and 
	// encryption algo.
	// Put the above Transforms
	// Initial len of Proposal Hdr is 8, since SPI is 0 initially.
	len = len + PROPOSAL_LEN;
	
#define TRANSFORM_SIZE 8
#define AES_PARAM_SIZE 4
// Repeat for each of the 4 transforms for IKE Proposal
	t = (ikev2_transform*)((char*)buff + len);
	// 3 indicates more transfors to come. 0 indicates last transform.
	t->type = 3;
	t->reserved= 0;
	t->transform_type = IKEV2_TRANSFORM_ENCR;
	PUT_BE16(t->transform_id, ike->ourProp.encr); // TODO: take as a param
	// Only when Enryption algo is AES
	// goto end of transform struct
	tmpPtr = (char*)buff + len + TRANSFORM_SIZE;
		/* Transform Attribute: Key Len = 128 bits */
		PUT_BE16(tmpPtr, 0x800e); /* AF=1, AttrType=14 */
		tmpPtr += 2;
		PUT_BE16(tmpPtr, 128); /* 128-bit key */
	PUT_BE16(t->transform_length, TRANSFORM_SIZE + AES_PARAM_SIZE);
	// We save each transform len in tlen variables
	tlen1 = TRANSFORM_SIZE + AES_PARAM_SIZE;
	len = len + tlen1;
// till here, with the last tranform having a the type set to 0.

// Next Transform
	t = (ikev2_transform*)((char*)buff + len);
	t->type = 3;
	t->reserved= 0;
	t->transform_type = IKEV2_TRANSFORM_PRF;
	PUT_BE16(t->transform_id, ike->ourProp.prf); // TODO: take as a param
	PUT_BE16(t->transform_length, TRANSFORM_SIZE);
	tlen2 = TRANSFORM_SIZE;
	len = len + tlen2;
//

// Next Transform
	t = (ikev2_transform*)((char*)buff + len);
	t->type = 3;
	t->reserved= 0;
	t->transform_type = IKEV2_TRANSFORM_INTEG;
	PUT_BE16(t->transform_id, ike->ourProp.integ); // TODO: take as a param
	PUT_BE16(t->transform_length, TRANSFORM_SIZE);
	tlen3 = TRANSFORM_SIZE;
	len = len + tlen3;
//

// Next Transform
	t = (ikev2_transform*)((char*)buff + len);
	t->type = 0;
	t->reserved= 0;
	t->transform_type = IKEV2_TRANSFORM_DH;
	PUT_BE16(t->transform_id, ike->ourProp.dh); // TODO: take as a param
	PUT_BE16(t->transform_length, TRANSFORM_SIZE);
	tlen4 = TRANSFORM_SIZE;
	len = len + tlen4;

	totalLen = PROPOSAL_LEN+tlen1+tlen2+tlen3+tlen4;
	PUT_BE16(p->proposal_length, totalLen);
	PUT_BE16(pHdr->payload_length, (totalLen+PAYLOAD_HDR_SIZE));
	printf("\n Security Payload Len = %d", totalLen+PAYLOAD_HDR_SIZE);

	/*
	 * Build Payload Key Exchange
	 */
	pHdr = (ikev2_payload_hdr*)((char*) buff+len);
	pHdr->next_payload = IKEV2_PAYLOAD_NONCE;
	pHdr->flags = 0;
	len = len + PAYLOAD_HDR_SIZE;
	tmpPtr = (char*)buff + len;
	PUT_BE16(tmpPtr, ike->ourProp.dh);
	tmpPtr += 2;
	PUT_BE16(tmpPtr, 0); // Reserved
	tmpPtr += 2;
	len = len+4;
	/* Calculate DH Public Value and copy it into the Key Data */
	ike->dh = dh_groups_get(ike->ourProp.dh);
	dhPublic = dh_init(ike->dh, &ike->i_dh_private);
	if(dhPublic == 0) {
		printf("\n Error getting DH Public value");
		fflush(stdout);
		return -1;
	}
	dHKeyLen = global_pv_len;
	memcpy(tmpPtr, dhPublic, dHKeyLen);
	hexdump(tmpPtr, dHKeyLen);

	PUT_BE16(pHdr->payload_length, (4+dHKeyLen+PAYLOAD_HDR_SIZE));
	printf("\n Key Exchange payload = %d, DH Public Value Len = %d",
				(4+dHKeyLen+PAYLOAD_HDR_SIZE), global_pv_len);
	len = len+dHKeyLen;

	/*
	 * Build Payload Nonce
	 */
	ike->i_nonce_len = 32;
	if (os_get_random(ike->i_nonce, ike->i_nonce_len)) {	
		printf("\nError: Unable to get 32 bytes of nonce");
		return -1;	
	}	
	pHdr = (ikev2_payload_hdr*)((char*) buff+len);
	pHdr->next_payload = IKEV2_PAYLOAD_NOTIFICATION;
	pHdr->flags = 0;
	len = len + PAYLOAD_HDR_SIZE;
	tmpPtr = (char*)buff + len;
	memcpy(tmpPtr, ike->i_nonce, 32); // 32 bytes of random nonce
	len = len + 32;
	PUT_BE16(pHdr->payload_length, (32+PAYLOAD_HDR_SIZE));
		printf("\n Nonce payload = %d", (32+PAYLOAD_HDR_SIZE));
		hexdump(ike->i_nonce, 32);
	/*
	 * Redirect Supported is sent as described in following RFC.
	 * http://www.rfc-editor.org/rfc/rfc5685.txt
	 */

	/*
	 * Build Redirect Notification
     *                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Next Payload  |C|  RESERVED   |         Payload Length        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Protocol ID(=0)| SPI Size (=0) |      Notify Message Type      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
	if (ike->redirected == FALSE) {
	printf("\nAdding Redirected Supported Payload");
	pHdr = (ikev2_payload_hdr*)((char*) buff+len);
	pHdr->next_payload = IKEV2_PAYLOAD_NO_NEXT_PAYLOAD;
	PUT_BE16(pHdr->payload_length, (4+PAYLOAD_HDR_SIZE));
	tmpPtr = (char*)buff + len + PAYLOAD_HDR_SIZE;
	memset(tmpPtr, 0, 4); // protocol id and spi_size values are 0
	tmpPtr += 2;
	PUT_BE16(tmpPtr, REDIRECT_SUPPORTED);
	len = len + 4 + PAYLOAD_HDR_SIZE;
	} else {

    /*                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Next Payload  |C|  RESERVED   |         Payload Length        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Protocol ID(=0)| SPI Size (=0) |      Notify Message Type      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | GW Ident Type |  GW Ident Len |                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               ~
    ~                   Original Responder GW Identity              ~
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	*/
	printf("\nAdding Redirected From Payload");
	pHdr = (ikev2_payload_hdr*)((char*) buff+len);
	pHdr->next_payload = IKEV2_PAYLOAD_NO_NEXT_PAYLOAD;
	PUT_BE16(pHdr->payload_length, (10+PAYLOAD_HDR_SIZE));
	tmpPtr = (char*)buff + len + PAYLOAD_HDR_SIZE;
	memset(tmpPtr, 0, 4); // protocol id and spi_size values are 0
	tmpPtr += 2;
	PUT_BE16(tmpPtr, REDIRECT_FROM);
	tmpPtr += 2;
	len = len + 4 + PAYLOAD_HDR_SIZE;
	*tmpPtr= 1; // GW Identity type = 1, indicating IPv4 address
	tmpPtr += 1; len++;
	*tmpPtr= 4; // GW Len = 4, for IPv4 addresses
	tmpPtr += 1; len++;
	// PUT_BE32(tmpPtr, ike->redirected_ip);
	// Put the original address here - i.e configured UT address
   	PUT_BE32(tmpPtr, inet_addr(cfg.utIP)); /* destination address */
	len = len +4;
	}

	// Put the total length
	PUT_BE32(hdr->length, len);
	printf("\n Total Len of IKE_INIT = %d", len);
	sendData(ike, buff, len);
	// Save this packet in a buffer in the ike struct, since for retransmission
	// we need to send the exact same packet back.
	memcpy(ike->saInitBuff, buff, len);
	ike->saInitLen = len;
	//startTimer(ike, 5);
}
