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

#include <mblty/ipsec.h>
#include <mblty/base-support.h>
#include <mipv6/protocol.h>
#include <mipv6/proto-sec.h>

static void ipsec_dyn_update(mipv6_binding_context_t *, mblty_address_t *);
static  int ipsec_is_valid(mipv6_binding_context_t *);
static void ipsec_release_auth_data(mipv6_auth_data_t *);

static mipv6_auth_data_ops_t ipsec_auth_data_ops = {
	.update = ipsec_dyn_update,
	.is_valid = ipsec_is_valid,
	.release = ipsec_release_auth_data,
};

struct mipv6_ipsec_auth_data {
	struct mipv6_auth_data base;

	struct ipsec_bidir_policy pol;

	struct mipv6_ipsec_dyn_ops *dyn_ops;
};

static inline struct mipv6_ipsec_auth_data *
ipsec_auth_data(mipv6_binding_context_t *ctx)
{
	return container_of(ctx->auth, struct mipv6_ipsec_auth_data, base);
}

static void
ipsec_check_valid_and_call(mipv6_binding_context_t *ctx)
{
	if (ctx->auth->updated && ipsec_is_valid(ctx))
		ctx->auth->updated(ctx->auth);
}

static void
ipsec_dyn_update(mipv6_binding_context_t *ctx, mblty_address_t *new_coa)
{
	struct mipv6_ipsec_auth_data *auth_data = ipsec_auth_data(ctx);

	if (auth_data->dyn_ops) {
		auth_data->dyn_ops->update(ctx, new_coa);
	} else {
		ipsec_check_valid_and_call(ctx);
	}
}

static int
ipsec_is_valid(mipv6_binding_context_t *ctx)
{
	struct mipv6_ipsec_auth_data *auth_data = ipsec_auth_data(ctx);

	return auth_data->pol.in.state == IPSEC_POLS_VALID &&
	       auth_data->pol.out.state == IPSEC_POLS_VALID;
}

static void
ipsec_pols_are_valid(struct ipsec_bidir_policy *p)
{
	mipv6_binding_context_t *ctx = p->owner;

	ipsec_check_valid_and_call(ctx);
}

mipv6_auth_data_t *
mipv6_alloc_ipsec_auth_data(mipv6_binding_context_t *ctx)
{
	struct mipv6_ipsec_auth_data *data;

	data = allocate_object(struct mipv6_ipsec_auth_data);
	if (data == NULL)
		return NULL;

	data->dyn_ops = NULL;

	ipsec_prepare_bidir_pol(&data->pol, mblty_get_addr(ctx->hoa),
				ctx->destination, 0, IPPROTO_MH,
				0 /* transport */, IPPROTO_ESP,
				0 /* required */);
	data->pol.owner = ctx;
	data->pol.are_valid = ipsec_pols_are_valid;

	ipsec_require_bidir_pol(&data->pol);

	return mipv6_auth_data_init(&data->base, ctx, &ipsec_auth_data_ops);
}

static void
ipsec_release_auth_data(mipv6_auth_data_t *auth_data)
{
	struct mipv6_ipsec_auth_data *data =
		container_of(auth_data, struct mipv6_ipsec_auth_data, base);

	debug_assert(auth_data->ops == &ipsec_auth_data_ops,
		     "Mismatched ipsec release auth strategy.");

	ipsec_release_bidir_pol(&data->pol);
	free_object(data);
}

