/*
 * MIPv6, an IPv6 mobility framework
 *
 * Copyright (C) 2006, 2007 Hugo Santos
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the version 2 of the GNU General Public License
 * as published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author:  Hugo Santos <hugo@fivebits.net>
 */

#ifndef _MIPV6_PRIV_PROTO_SEC_H_
#define _MIPV6_PRIV_PROTO_SEC_H_

#include <mipv6/proto-defs.h>

struct mipv6_auth_data_ops {
	void (*auth_bu)(mipv6_binding_context_t *, mipv6_mh_bld_ctx_t *);
	int (*auth_bu_ack)(mipv6_binding_context_t *, struct in6_addr *,
			   struct ip6_mh_binding_ack *, size_t length);
	void (*update)(mipv6_binding_context_t *, mblty_address_t *);
	/* if address is supplied, we only cancel if the pending address
	 * is the same as the address supplied */
	void (*cancel)(mipv6_binding_context_t *, mblty_address_t *);
	void (*clear)(mipv6_binding_context_t *);
	/* returns 0 if the context is not currently authenticated */
	int (*is_valid)(mipv6_binding_context_t *);
	void (*release)(mipv6_auth_data_t *);
};

struct mipv6_auth_data {
	mipv6_binding_context_t *parent;
	mipv6_auth_data_ops_t *ops;

	void (*updated)(struct mipv6_auth_data *);
	void (*failed)(struct mipv6_auth_data *);
};

struct mipv6_ipsec_dyn_ops {
	void (*update)(mipv6_binding_context_t *, mblty_address_t *);
	void (*cancel)(mipv6_binding_context_t *);
};

struct mipv6_responder_auth_ops {
	int (*auth_bu)(mipv6_responder_auth_t *, mipv6_responder_auth_data_t **,
		       struct in6_addr *, struct in6_addr *, mipv6_msgctx_t *);
	void (*release)(mipv6_responder_auth_t *);
};

struct mipv6_responder_auth {
	mipv6_responder_auth_ops_t *ops;
};

struct mipv6_responder_auth_data_ops {
	void (*auth_bu_ack)(mipv6_responder_auth_data_t *, mipv6_mh_bld_ctx_t *,
			    struct in6_addr *hoa, struct in6_addr *coa,
			    struct in6_addr *dst);
	mipv6_responder_auth_data_t *(*clone)(mipv6_responder_auth_data_t *);
	void (*release)(mipv6_responder_auth_data_t *);
};

struct mipv6_responder_auth_data {
	mipv6_responder_auth_data_ops_t *ops;
};

uint16_t mipv6_generate_rand_uint16();

mipv6_auth_data_t *mipv6_auth_data_init(mipv6_auth_data_t *,
					mipv6_binding_context_t *,
					mipv6_auth_data_ops_t *);
void mipv6_auth_data_update(mipv6_binding_context_t *, mblty_address_t *);
void mipv6_auth_data_cancel(mipv6_binding_context_t *, mblty_address_t *);
void mipv6_auth_data_clear(mipv6_binding_context_t *);
int mipv6_auth_data_is_valid(mipv6_binding_context_t *);
void mipv6_auth_data_release(mipv6_auth_data_t *);

void mipv6_proto_rr_init();

struct mipv6_auth_data *mipv6_alloc_rr_auth_data(mipv6_binding_context_t *);
struct mipv6_auth_data *mipv6_alloc_ipsec_auth_data(mipv6_binding_context_t *);

mipv6_responder_auth_t *mipv6_rr_obtain_resp_auth();

#endif

