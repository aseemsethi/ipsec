/*
 * IKEv2 common routines for initiator and responder
 * Copyright (c) 2007, Jouni Malinen <j@w1.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */
#include "sim.h"
#include "crypto/crypto.h"
//extern ipsecCfg cfg;

spidump(unsigned char* buf, int len) {
	int i;
	for (i = len-1; i >= 0; i--)
		printf("%02x", buf[i]);
}

hexdump(unsigned char* buf, int len) {
	int i;
	for (i = 0; i < len; i++)
		printf(" %02x", buf[i]);
}

static struct ikev2_integ_alg ikev2_integ_algs[] = {
	{ AUTH_HMAC_SHA1_96, 20, 12 },
	{ AUTH_HMAC_MD5_96, 16, 12 }
};

#define NUM_INTEG_ALGS (sizeof(ikev2_integ_algs) / sizeof(ikev2_integ_algs[0]))


static struct ikev2_prf_alg ikev2_prf_algs[] = {
	{ PRF_HMAC_SHA1, 20, 20 },
	{ PRF_HMAC_MD5, 16, 16 }
};

#define NUM_PRF_ALGS (sizeof(ikev2_prf_algs) / sizeof(ikev2_prf_algs[0]))


static struct ikev2_encr_alg ikev2_encr_algs[] = {
	{ ENCR_AES_CBC, 16, 16 }, /* only 128-bit keys supported for now */
	{ ENCR_3DES, 24, 8 }
};

#define NUM_ENCR_ALGS (sizeof(ikev2_encr_algs) / sizeof(ikev2_encr_algs[0]))

const struct ikev2_integ_alg * ikev2_get_integ(int id)
{
	size_t i;

	for (i = 0; i < NUM_INTEG_ALGS; i++) {
		if (ikev2_integ_algs[i].id == id)
			return &ikev2_integ_algs[i];
	}

	return NULL;
}


int ikev2_integ_hash(int alg, const u8 *key, size_t key_len, const u8 *data,
		     size_t data_len, u8 *hash)
{
	u8 tmphash[IKEV2_MAX_HASH_LEN];

	switch (alg) {
	case AUTH_HMAC_SHA1_96:
		if (key_len != 20)
			return -1;
		hmac_sha1(key, key_len, data, data_len, tmphash);
		memcpy(hash, tmphash, 12);
		break;
	case AUTH_HMAC_MD5_96:
		if (key_len != 16)
			return -1;
		hmac_md5(key, key_len, data, data_len, tmphash);
		memcpy(hash, tmphash, 12);
		break;
	default:
		return -1;
	}

	return 0;
}

const struct ikev2_prf_alg * ikev2_get_prf(int id)
{
	size_t i;

	for (i = 0; i < NUM_PRF_ALGS; i++) {
		if (ikev2_prf_algs[i].id == id)
			return &ikev2_prf_algs[i];
	}

	return NULL;
}


int ikev2_prf_hash(int alg, const u8 *key, size_t key_len,
		   size_t num_elem, const u8 *addr[], const size_t *len,
		   u8 *hash)
{
	switch (alg) {
	case PRF_HMAC_SHA1:
		hmac_sha1_vector(key, key_len, num_elem, addr, len, hash);
		break;
	case PRF_HMAC_MD5:
		hmac_md5_vector(key, key_len, num_elem, addr, len, hash);
		break;
	default:
		return -1;
	}

	return 0;
}

int ikev2_prf_plus(int alg, const u8 *key, size_t key_len,
		   const u8 *data, size_t data_len,
		   u8 *out, size_t out_len)
{
	u8 hash[IKEV2_MAX_HASH_LEN];
	size_t hash_len;
	u8 iter, *pos, *end;
	const u8 *addr[3];
	size_t len[3];
	const struct ikev2_prf_alg *prf;
	int res;

	prf = ikev2_get_prf(alg);
	if (prf == NULL)
		return -1;
	hash_len = prf->hash_len;

	addr[0] = hash;
	len[0] = hash_len;
	addr[1] = data;
	len[1] = data_len;
	addr[2] = &iter;
	len[2] = 1;

	pos = out;
	end = out + out_len;
	iter = 1;
	while (pos < end) {
		size_t clen;
		if (iter == 1)
			res = ikev2_prf_hash(alg, key, key_len, 2, &addr[1],
					     &len[1], hash);
		else
			res = ikev2_prf_hash(alg, key, key_len, 3, addr, len,
					     hash);
		if (res < 0)
			return -1;
		clen = hash_len;
		if ((int) clen > end - pos)
			clen = end - pos;
		memcpy(pos, hash, clen);
		pos += clen;
		iter++;
	}

	return 0;
}


const struct ikev2_encr_alg * ikev2_get_encr(int id)
{
	size_t i;

	for (i = 0; i < NUM_ENCR_ALGS; i++) {
		if (ikev2_encr_algs[i].id == id)
			return &ikev2_encr_algs[i];
	}

	return NULL;
}


/* from des.c */
struct des3_key_s {
	u32 ek[3][32];
	u32 dk[3][32];
};


#if 0
int os_get_random(unsigned char *buf, size_t len)
{
	FILE *f;
	size_t rc;

	f = fopen("/dev/urandom", "rb");
	if (f == NULL) {
		printf("Could not open /dev/urandom.\n");
		return -1;
	}

	rc = fread(buf, 1, len, f);
	fclose(f);

	return rc != len ? -1 : 0;
}
#endif

void ikev2_free_keys(struct ikev2_keys *keys)
{
	free(keys->SK_d);
	free(keys->SK_ai);
	free(keys->SK_ar);
	free(keys->SK_ei);
	free(keys->SK_er);
	free(keys->SK_pi);
	free(keys->SK_pr);
	keys->SK_d = keys->SK_ai = keys->SK_ar = keys->SK_ei = keys->SK_er =
				keys->SK_pi = keys->SK_pr = NULL;
}

int ikev2_keys_set(struct ikev2_keys *keys)
{
	return keys->SK_d && keys->SK_ai && keys->SK_ar && keys->SK_ei &&
			keys->SK_er && keys->SK_pi && keys->SK_pr;
}

int ikev2_derive_sk_keys(const struct ikev2_prf_alg *prf,
			 const struct ikev2_integ_alg *integ,
			 const struct ikev2_encr_alg *encr,
			 const u8 *skeyseed, const u8 *data, size_t data_len,
			 struct ikev2_keys *keys)
{
	u8 *keybuf, *pos;
	size_t keybuf_len;

	/*
	 * {SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr } =
	 *	prf+(SKEYSEED, Ni | Nr | SPIi | SPIr )
	 */
	ikev2_free_keys(keys);
	keys->SK_d_len = prf->key_len;
	keys->SK_integ_len = integ->key_len;
	keys->SK_encr_len = encr->key_len;
	keys->SK_prf_len = prf->key_len;
#ifdef CCNS_PL
	/* Uses encryption key length for SK_d; should be PRF length */
	keys->SK_d_len = keys->SK_encr_len;
#endif /* CCNS_PL */

	keybuf_len = keys->SK_d_len + 2 * keys->SK_integ_len +
		2 * keys->SK_encr_len + 2 * keys->SK_prf_len;
	keybuf = malloc(keybuf_len);
	if (keybuf == NULL)
		return -1;

	if (ikev2_prf_plus(prf->id, skeyseed, prf->hash_len,
			   data, data_len, keybuf, keybuf_len)) {
		free(keybuf);
		return -1;
	}

	pos = keybuf;

	keys->SK_d = malloc(keys->SK_d_len);
	if (keys->SK_d) {
		memcpy(keys->SK_d, pos, keys->SK_d_len);
			printf("\nIKEV2: SK_d  %d:", keys->SK_d_len);
			hexdump(keys->SK_d, keys->SK_d_len);
	}
	pos += keys->SK_d_len;

	keys->SK_ai = malloc(keys->SK_integ_len);
	if (keys->SK_ai) {
		memcpy(keys->SK_ai, pos, keys->SK_integ_len);
			printf("\nIKEV2: SK_ai %d:",keys->SK_integ_len);
			hexdump(keys->SK_ai, keys->SK_integ_len);
	}
	pos += keys->SK_integ_len;

	keys->SK_ar = malloc(keys->SK_integ_len);
	if (keys->SK_ar) {
		memcpy(keys->SK_ar, pos, keys->SK_integ_len);
				printf("\nIKEV2: SK_ar %d:", keys->SK_integ_len);
				hexdump(keys->SK_ar, keys->SK_integ_len);
	}
	pos += keys->SK_integ_len;

	keys->SK_ei = malloc(keys->SK_encr_len);
	if (keys->SK_ei) {
		memcpy(keys->SK_ei, pos, keys->SK_encr_len);
			printf("\nIKEV2: SK_ei %d:", keys->SK_encr_len);
			hexdump(keys->SK_ei, keys->SK_encr_len);
	}
	pos += keys->SK_encr_len;

	keys->SK_er = malloc(keys->SK_encr_len);
	if (keys->SK_er) {
		memcpy(keys->SK_er, pos, keys->SK_encr_len);
			printf("\nIKEV2: SK_er %d:", keys->SK_encr_len);
			hexdump(keys->SK_er, keys->SK_encr_len);
	}
	pos += keys->SK_encr_len;

	keys->SK_pi = malloc(keys->SK_prf_len);
	if (keys->SK_pi) {
		memcpy(keys->SK_pi, pos, keys->SK_prf_len);
			printf("\nIKEV2: SK_pi %d:", keys->SK_prf_len);
			hexdump(keys->SK_pi, keys->SK_prf_len);
	}
	pos += keys->SK_prf_len;

	keys->SK_pr = malloc(keys->SK_prf_len);
	if (keys->SK_pr) {
		memcpy(keys->SK_pr, pos, keys->SK_prf_len);
			printf("\nIKEV2: SK_pr %d:", keys->SK_prf_len);
			hexdump(keys->SK_pr, keys->SK_prf_len);
	}

	free(keybuf);

	if (!ikev2_keys_set(keys)) {
		ikev2_free_keys(keys);
		return -1;
	}

	return 0;
}

int ikev2_encr_encrypt(int alg, const u8 *key, size_t key_len, const u8 *iv,
		       const u8 *plain, u8 *crypt, size_t len)
{
	struct crypto_cipher *cipher;
	int encr_alg;

#ifdef CCNS_PL
	if (alg == ENCR_3DES) {
		struct des3_key_s des3key;
		size_t i, blocks;
		u8 *pos;

		/* ECB mode is used incorrectly for 3DES!? */
		if (key_len != 24) {
			printf("IKEV2: Invalid encr key length");
			return -1;
		}
		des3_key_setup(key, &des3key);

		blocks = len / 8;
		pos = crypt;
		for (i = 0; i < blocks; i++) {
			des3_encrypt(pos, &des3key, pos);
			pos += 8;
		}
	} else {
#endif /* CCNS_PL */
	switch (alg) {
	case ENCR_3DES:
		encr_alg = CRYPTO_CIPHER_ALG_3DES;
		break;
	case ENCR_AES_CBC:
		encr_alg = CRYPTO_CIPHER_ALG_AES;
		break;
	default:
		printf("IKEV2: Unsupported encr alg %d", alg);
		return -1;
	}

	cipher = crypto_cipher_init(encr_alg, iv, key, key_len);
	if (cipher == NULL) {
		printf("IKEV2: Failed to initialize cipher");
		return -1;
	}

	if (crypto_cipher_encrypt(cipher, plain, crypt, len) < 0) {
		printf("IKEV2: Encryption failed");
		crypto_cipher_deinit(cipher);
		return -1;
	}
	crypto_cipher_deinit(cipher);
#ifdef CCNS_PL
	}
#endif /* CCNS_PL */

	return 0;
}
int ikev2_build_encrypted(int encr_id, int integ_id, struct ikev2_keys *keys,
		  int initiator, unsigned char *msg, unsigned char *plain, 
		  u8 next_payload, int msg_len, unsigned char *msg_start, 
		  int plain_len)
{
	ikev2_payload_hdr *phdr;
	size_t plen;
	size_t iv_len, pad_len;
	u8 *icv, *iv;
	const struct ikev2_integ_alg *integ_alg;
	const struct ikev2_encr_alg *encr_alg;
	const u8 *SK_e = initiator ? keys->SK_ei : keys->SK_er;
	const u8 *SK_a = initiator ? keys->SK_ai : keys->SK_ar;
	int len=0;
	ikev2_hdr *hdr;
	hdr = (ikev2_hdr*)msg_start;

	// printf("\nIKEV2: Adding Encrypted payload");

	/* Encr - RFC 4306, Sect. 3.14 */

	encr_alg = ikev2_get_encr(encr_id);
	if (encr_alg == NULL) {
		printf("IKEV2: Unsupported encryption type");
		return -1;
	}
	iv_len = encr_alg->block_size;

	integ_alg = ikev2_get_integ(integ_id);
	if (integ_alg == NULL) {
		printf("IKEV2: Unsupported intergrity type");
		return -1;
	}

	if (SK_e == NULL) {
		printf("IKEV2: No SK_e available");
		return -1;
	}

	if (SK_a == NULL) {
		printf("IKEV2: No SK_a available");
		return -1;
	}

	phdr = (ikev2_payload_hdr*) msg;
	len = len + PAYLOAD_HDR_SIZE;
	phdr->next_payload = next_payload;
	phdr->flags = 0;

	iv = msg +len;
	len = len + iv_len;
	if (os_get_random(iv, iv_len)) {
		printf("IKEV2: Could not generate IV");
		return -1;
	}

	pad_len = iv_len - (plain_len + 1) % iv_len;
	if (pad_len == iv_len)
		pad_len = 0;
	if (pad_len != 0) {
		printf("\n pad len in encryption module = %d", pad_len);
		// wpabuf_put(plain, pad_len);
		memset(&plain[plain_len], 0, pad_len);
		plain_len += pad_len;
		// wpabuf_put_u8(plain, pad_len);
		plain[plain_len] = pad_len;
		plain_len += 1;
	}

	if (ikev2_encr_encrypt(encr_alg->id, SK_e, keys->SK_encr_len, iv,
			       plain, plain, plain_len) < 0)
		return -1;

	//wpabuf_put_buf(msg, plain);
	memcpy(msg+len, plain, plain_len);

	/* Need to update all headers (Length fields) prior to hash func */
	icv = &msg[len + plain_len];
	len = len + plain_len + integ_alg->hash_len;
	PUT_BE16(phdr->payload_length, len);

	//ikev2_update_hdr(msg);
	PUT_BE32(hdr->length, msg_len+len);
	printf("\nIKE Auth pkt with encryption size = %d", msg_len + len);
	return ikev2_integ_hash(integ_id, SK_a, keys->SK_integ_len,
				msg_start,
				msg_len + len - integ_alg->hash_len, icv);

	return 0;
}


int ikev2_encr_decrypt(int alg, const u8 *key, size_t key_len, const u8 *iv,
		       const u8 *crypt, u8 *plain, size_t len)
{
	struct crypto_cipher *cipher;
	int encr_alg;

#ifdef CCNS_PL
	if (alg == ENCR_3DES) {
		struct des3_key_s des3key;
		size_t i, blocks;

		/* ECB mode is used incorrectly for 3DES!? */
		if (key_len != 24) {
			wpa_printf(MSG_INFO, "IKEV2: Invalid encr key length");
			return -1;
		}
		des3_key_setup(key, &des3key);

		if (len % 8) {
			wpa_printf(MSG_INFO, "IKEV2: Invalid encrypted "
				   "length");
			return -1;
		}
		blocks = len / 8;
		for (i = 0; i < blocks; i++) {
			des3_decrypt(crypt, &des3key, plain);
			plain += 8;
			crypt += 8;
		}
	} else {
#endif /* CCNS_PL */
	switch (alg) {
	case ENCR_3DES:
		encr_alg = CRYPTO_CIPHER_ALG_3DES;
		break;
	case ENCR_AES_CBC:
		encr_alg = CRYPTO_CIPHER_ALG_AES;
		break;
	default:
		printf("IKEV2: Unsupported encr alg %d", alg);
		return -1;
	}

	cipher = crypto_cipher_init(encr_alg, iv, key, key_len);
	if (cipher == NULL) {
		printf("IKEV2: Failed to initialize cipher");
		return -1;
	}

	if (crypto_cipher_decrypt(cipher, crypt, plain, len) < 0) {
		printf("IKEV2: Decryption failed");
		crypto_cipher_deinit(cipher);
		return -1;
	}
	crypto_cipher_deinit(cipher);
#ifdef CCNS_PL
	}
#endif /* CCNS_PL */

	return 0;
}


