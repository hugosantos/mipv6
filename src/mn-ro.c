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

#include <mblty/address.h>
#include <mblty/interface.h>
#include <mblty/base-support.h>

#include <mipv6/os.h>
#include <mipv6/mipv6.h>
#include <mipv6/mn-hoa.h>

#define MN_IND_GC_TIMEOUT	15000
#define MN_INDIVIDUAL_LIFETIME	60000

void mipv6_mn_ro_state_init();

static int mipv6_mn_gc_users = 0;
static suptimer_t mipv6_mn_gc;

static void
mn_need_ctx_gc(int inc)
{
	int prev = mipv6_mn_gc_users;

	mipv6_mn_gc_users += inc;

	if (prev == 0 && mipv6_mn_gc_users == 1)
		timer_add(&mipv6_mn_gc, MN_IND_GC_TIMEOUT);
	else if (prev == 1 && mipv6_mn_gc_users == 0)
		timer_remove(&mipv6_mn_gc);
}

static void
mn_hoa_dettach_individual(struct mipv6_mn_individual *ctx)
{
	/* already released? */
	if (ctx == NULL || ctx->parent == NULL)
		return;

	list_del(&ctx->entry);
	ctx->parent = NULL;

	mn_need_ctx_gc(-1);
}

static void
mn_hoa_remove_individual(struct mipv6_mn_individual *ctx)
{
	mn_hoa_dettach_individual(ctx);
	mipv6_remove_binding_context(&ctx->binding_ctx);

	mipv6_auth_data_release(ctx->binding_ctx.auth);
	ctx->binding_ctx.auth = NULL;

	if (ctx->ops->destructor)
		ctx->ops->destructor(ctx);
	else
		free_object(ctx);
}

static void
mn_indiv_expired(struct mipv6_mn_individual *ctx)
{
	debug_log(4, "mn_indiv_expired(%p)\n", ctx);

	if (ctx->ops->expired)
		ctx->ops->expired(ctx);

	ctx->binding_ctx.flags |= MIPV6_BCTX_EXPIRED;

	mn_hoa_remove_individual(ctx);
}

static int
mn_check_individual(struct mipv6_mn_individual *ctx, void *nowptr)
{
	uint64_t *now = nowptr;
	uint64_t diff;

	diff = (*now) - ctx->st_last_update;

	if (ctx->flags & MIPV6_MN_IND_PERMANENT)
		return 0;

	if (ctx->flags & MIPV6_MN_IND_AUTHERR) {
		if ((*now - ctx->last_required) >= MN_INDIVIDUAL_LIFETIME) {
			mn_indiv_expired(ctx);
		} else if (diff >= (2 * MN_INDIVIDUAL_LIFETIME)) {
			debug_log(3, "Clearing error status\n");
			ctx->flags &= ~MIPV6_MN_IND_AUTHERR;
		}
	} else if (diff >= MN_INDIVIDUAL_LIFETIME) {
		uint32_t value;

		if (kern_bcache_get_stat(mblty_get_addr(&ctx->parent->a),
					 &ctx->remote, &value) < 0)
			value = ctx->st_last_value;

		if (value == ctx->st_last_value) {
			mn_indiv_expired(ctx);
		} else {
			ctx->st_last_value = value;
			ctx->st_last_update = *now;
		}
	}

	return 0;
}

static int
mn_check_hoa_individuals(struct mipv6_mn_hoa *hoa, void *nowptr)
{
	mipv6_mn_foreach_hoa_individual(hoa, mn_check_individual, nowptr);
	return 0;
}

static void
mn_run_gc(suptimer_t *tmr, void *arg)
{
	uint64_t now = support_get_sys_timestamp();

	mn_need_ctx_gc(+1);
	mipv6_mn_foreach_hoa(mn_check_hoa_individuals, &now);
	timer_add(&mipv6_mn_gc, MN_IND_GC_TIMEOUT);
	mn_need_ctx_gc(-1);
}

void
mipv6_mn_foreach_hoa_individual(struct mipv6_mn_hoa *hoa,
				int (*cb)(struct mipv6_mn_individual *,
				void *), void *param)
{
	struct mipv6_mn_individual *ind, *tmp;

	list_for_each_entry_safe (ind, tmp, &hoa->individual_ctxs, entry) {
		if (cb(ind, param) < 0)
			return;
	}

}

static int
mn_remove_indiv_adaptor(struct mipv6_mn_individual *ind, void *arg)
{
	mn_hoa_remove_individual(ind);
	return 0;
}

static int
mn_hoa_check_indiv(struct mipv6_mn_individual *ind, void *addrptr)
{
	mblty_address_t *address = addrptr;

	mipv6_auth_data_cancel(&ind->binding_ctx, address);

	/* Check if the individual is using the specified
	 * (which is being lost) address. If so, invalidate
	 * the binding immediatly. If another address is
	 * available we are in the middle of an Handover and
	 * the state will be updated shortly. */
	if (ind->binding_ctx.coa == address)
		mipv6_clear_binding(&ind->binding_ctx);

	return 0;
}

static void
mn_hoa_check_invalid_ind(struct mipv6_mn_hoa *hoa, mblty_address_t *address)
{
	mipv6_mn_foreach_hoa_individual(hoa, mn_hoa_check_indiv, address);
}

static int
mn_hoa_update_indiv(struct mipv6_mn_individual *ctx, void *arg)
{
	if (ctx->flags & MIPV6_MN_IND_LOCKED ||
	    ctx->flags & MIPV6_MN_IND_AUTHERR)
		return 0;

	if (!(ctx->flags & MIPV6_MN_IND_NEEDS_UPDATE))
		return 0;

	ctx->flags &= ~MIPV6_MN_IND_NEEDS_UPDATE;
	ctx->flags |= MIPV6_MN_IND_PREPARING;

	ctx->st_last_update = support_get_sys_timestamp();

	ctx->ops->prepare(ctx);

	return 0;
}

static void
mn_hoa_indiv_cancel_preparation(struct mipv6_mn_individual *ctx)
{
	ctx->flags &= ~MIPV6_MN_IND_PREPARING;
	mipv6_auth_data_cancel(&ctx->binding_ctx, NULL);
}

static int
mn_hoa_invalidate_indiv(struct mipv6_mn_individual *ind, void *arg)
{
	mblty_network_address_t *head = arg;
	mblty_address_t *headp;

	headp = mblty_addr_parent(head);

	if (head && ind->binding_ctx.coa == headp) {
		if (ind->flags & MIPV6_MN_IND_PREPARING) {
			/* this call will only update the address pointer
			 * and won't restart the on-going signaling */
			ind->ops->prepare(ind);
		} else if (!(ind->flags & MIPV6_MN_IND_NEEDS_UPDATE)) {
			/* if the state is stable, update the address
			 * pointer being used in the binding */
			mipv6_update_binding(&ind->binding_ctx, headp);
		}

		return 0;
	}


	if (ind->flags & MIPV6_MN_IND_PREPARING)
		mn_hoa_indiv_cancel_preparation(ind);

	if (ind->flags & MIPV6_MN_IND_AUTHERR)
		return 0;

	ind->flags |= MIPV6_MN_IND_NEEDS_UPDATE;

	return 0;
}

struct mipv6_mn_individual *
mipv6_mn_hoa_get_individual(struct mipv6_mn_hoa *hoa, struct in6_addr *address)
{
	struct mipv6_mn_individual *ctx;

	list_for_each_entry (ctx, &hoa->individual_ctxs, entry) {
		if (in6_addr_compare(&ctx->remote, address) == 0)
			return ctx;
	}

	return NULL;
}

void
mipv6_mn_unlock_individual(struct mipv6_mn_individual *ctx)
{
	if (!(ctx->flags & MIPV6_MN_IND_LOCKED))
		return;

	ctx->flags &= ~MIPV6_MN_IND_LOCKED;

	mipv6_mn_individual_update(ctx);
}

static void
mn_hoa_indiv_done_preparing(struct mipv6_mn_individual *ctx)
{
	mblty_network_address_t *coa = mipv6_mn_hoa_active_coa(ctx->parent);
	int at_home = (ctx->parent->location == MIPV6_MN_LOC_HOME);

	debug_assert(ctx->flags & MIPV6_MN_IND_PREPARING,
		     "Called done preparing on non-preparing individual");

	ctx->flags &= ~MIPV6_MN_IND_PREPARING;

	if (at_home)
		coa = NULL;

	mipv6_update_binding(&ctx->binding_ctx, mblty_addr_parent(coa));

	/* Only clear data after sending BU as it is
	 * needed to authenticate it */
	if (at_home)
		mipv6_auth_data_clear(&ctx->binding_ctx);
}

static void
mn_prepare_individual(struct mipv6_mn_individual *ctx)
{
	struct mipv6_auth_data *auth = ctx->binding_ctx.auth;
	mipv6_mn_hoa_t *hoa = ctx->parent;

	if (auth && auth->ops->update && hoa->location != MIPV6_MN_LOC_HOME)
		mipv6_auth_data_update(&ctx->binding_ctx, mblty_addr_parent(
				       mipv6_mn_hoa_active_coa(hoa)));
	else
		mn_hoa_indiv_done_preparing(ctx);
}

static void
mn_hoa_attach_individual(struct mipv6_mn_hoa *hoa,
			 struct mipv6_mn_individual *ctx)
{
	ctx->parent = hoa;

	list_add_tail(&ctx->entry, &hoa->individual_ctxs);

	mn_need_ctx_gc(+1);
}

static void
mn_hoa_indiv_almost_done_prep(struct mipv6_auth_data *auth_data)
{
	struct mipv6_mn_individual *indctx = auth_data->parent->owner;

	if (indctx->flags & MIPV6_MN_IND_PREPARING)
		mn_hoa_indiv_done_preparing(indctx);
}

static void
mn_hoa_indiv_auth_failed(struct mipv6_auth_data *auth_data)
{
	struct mipv6_mn_individual *indctx = auth_data->parent->owner;

	/* hold this context for 60s */

	indctx->flags &= ~MIPV6_MN_IND_PREPARING;
	indctx->flags |= MIPV6_MN_IND_AUTHERR;

	mipv6_update_binding(&indctx->binding_ctx, NULL);
}

void
mipv6_mn_individual_is_required(struct mipv6_mn_individual *ctx)
{
	ctx->last_required = support_get_sys_timestamp();

	if (ctx->flags & MIPV6_MN_IND_PREPARING)
		return;

	if (mipv6_auth_data_is_valid(&ctx->binding_ctx))
		return;

	ctx->flags |= MIPV6_MN_IND_NEEDS_UPDATE;

	mipv6_mn_individual_update(ctx);
}

static void
mn_indiv_bctx_completed_reg(struct mipv6_binding_context *ctx)
{
	struct mipv6_mn_individual *indctx = ctx->owner;

	if (indctx->ops->completed_reg)
		indctx->ops->completed_reg(indctx);
}

void
mipv6_mn_individual_update(struct mipv6_mn_individual *ctx)
{
	mn_hoa_update_indiv(ctx, NULL);
}

void
mipv6_mn_trigger_ro(struct in6_addr *hoa, struct in6_addr *address)
{
	struct mipv6_mn_hoa *instance;
	struct mipv6_mn_individual *ind;

	instance = mipv6_mn_get_hoa(hoa);
	if (instance == NULL)
		return;

	if (mipv6_mn_hoa_get_individual(instance, address) != NULL)
		return;

	ind = mipv6_mn_hoa_alloc_individual(instance, address);
	if (ind == NULL)
		return;

	mipv6_mn_unlock_individual(ind);
}

void
mipv6_mn_stop_ro(struct in6_addr *hoa, struct in6_addr *address)
{
	struct mipv6_mn_individual *ind;
	struct mipv6_mn_hoa *instance;

	instance = mipv6_mn_get_hoa(hoa);
	if (instance == NULL)
		return;

	ind = mipv6_mn_hoa_get_individual(instance, address);
	if (ind == NULL)
		return;

	mn_hoa_remove_individual(ind);
}

static void
mn_hoa_ro_pre_update(mipv6_mn_hoa_t *hoa, mblty_network_address_t *addr)
{
	mipv6_mn_foreach_hoa_individual(hoa, mn_hoa_invalidate_indiv, addr);
}

static void
mn_hoa_ro_post_update(mipv6_mn_hoa_t *hoa)
{
	mipv6_mn_foreach_hoa_individual(hoa, mn_hoa_update_indiv, NULL);
}

static void
mn_hoa_ro_clear_state(mipv6_mn_hoa_t *hoa)
{
	/* release all individual contexts */
	mipv6_mn_foreach_hoa_individual(hoa, mn_remove_indiv_adaptor, NULL);
}

static void
mn_hoa_ro_invalidate_addr(mipv6_mn_hoa_t *hoa, mblty_network_address_t *addr)
{
	mn_hoa_check_invalid_ind(hoa, mblty_addr_parent(addr));
}

static void
mipv6_mn_ro_state_shutdown()
{
	if (mipv6_mn_gc_users > 0)
		timer_remove(&mipv6_mn_gc);
}

static struct mblty_shutdown_entry mn_ro_state_shutdown = {
	.handler = mipv6_mn_ro_state_shutdown,
};

struct mipv6_mn_binding_ops mipv6_mn_ro_binding_ops = {
	.pre_update = mn_hoa_ro_pre_update,
	.post_update = mn_hoa_ro_post_update,
	.invalidate_addr = mn_hoa_ro_invalidate_addr,
	.clear_state = mn_hoa_ro_clear_state,
};

static struct mipv6_mn_individual_ops ind_default_ops = {
	.prepare = mn_prepare_individual,
	.destructor = NULL,
};

struct mipv6_mn_individual *
mipv6_mn_hoa_alloc_individual(struct mipv6_mn_hoa *hoa,
			      struct in6_addr *remote)
{
	struct mipv6_auth_data *auth_data;
	struct mipv6_mn_individual *ctx;

	ctx = allocate_object(struct mipv6_mn_individual);
	if (ctx == NULL)
		return NULL;

	ctx->parent = NULL;
	in6_addr_copy(&ctx->remote, remote);

	mipv6_init_binding_context(&ctx->binding_ctx, hoa->binding_ctx.hoa,
				   &ctx->remote);

	ctx->binding_ctx.parent = &hoa->binding_ctx;
	ctx->binding_ctx.owner = ctx;
	ctx->binding_ctx.flags = 0;
	ctx->binding_ctx.cb_completed_reg = mn_indiv_bctx_completed_reg;

	/* clear any previous binding */
	mipv6_update_binding(&ctx->binding_ctx, NULL);

	auth_data = mipv6_alloc_rr_auth_data(&ctx->binding_ctx);
	auth_data->updated = mn_hoa_indiv_almost_done_prep;
	auth_data->failed = mn_hoa_indiv_auth_failed;
	ctx->binding_ctx.auth = auth_data;

	ctx->flags = MIPV6_MN_IND_LOCKED | MIPV6_MN_IND_NEEDS_UPDATE;
	ctx->ops = &ind_default_ops;

	ctx->last_required = ctx->st_last_update = support_get_sys_timestamp();
	ctx->st_last_value = 0;

	mn_hoa_attach_individual(hoa, ctx);

	return ctx;
}

void
mipv6_mn_ro_state_init()
{
	timer_init_with(&mipv6_mn_gc, "ind ctx gc", mn_run_gc, NULL);
	mblty_register_shutdown(&mn_ro_state_shutdown);
}

