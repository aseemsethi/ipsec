/*
 * Diffie-Hellman groups
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

#ifndef DH_GROUPS_H
#define DH_GROUPS_H

struct dh_group {
	int id;
	const u8 *generator;
	size_t generator_len;
	const u8 *prime;
	size_t prime_len;
};

struct dh_group * dh_groups_get(int id);
void* dh_init(const struct dh_group *dh, unsigned char **priv);
void* dh_derive_shared(void *peer_public,
				 void *own_private,
				 const struct dh_group *dh, 
				size_t *shared_len, size_t public_len);

#endif /* DH_GROUPS_H */

