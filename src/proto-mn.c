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

#include <mblty/router.h>
#include <mblty/base-support.h>
#include <mblty/sock-support.h>

#include <mipv6/os.h>
#include <mipv6/mipv6.h>
#include <mipv6/protocol.h>
#include <mipv6/proto-sec.h>

#define MIPV6_INITIAL_BINDACK_TIMEOUT		1000
#define MIPV6_INITIAL_BINDACK_TIMEOUT_FIRST_REG	1500
#define MIPV6_MAX_BINDACK_TIMEOUT		32000

#define MIPV6_RETRY_AFTER_ERROR_TIMEOUT	120000

#define MIN(x,y)			((x) < (y) ? (x) : (y))

static void bctx_send_binding_update(struct mipv6_binding_context *ctx);

static LIST_DEF(binding_update_list);

static inline struct in6_addr *
bctx_hoa(struct mipv6_binding_context *ctx)
{
	return mblty_get_addr(ctx->hoa);
}

static inline struct in6_addr *
bctx_coa(struct mipv6_binding_context *ctx)
{
	if (ctx->coa == NULL)
		return NULL;
	return &ctx->coa->address;
}

static inline struct in6_addr *
bce_coa(struct mipv6_bcache_entry *bce)
{
	if (bce->flags & MIPV6_BCE_VALID)
		return &bce->active_coa;
	return NULL;
}

/* return best match from binding_update_list in regards
 * to (hoa,coa,remote) tuple. */
struct mipv6_binding_context *
mipv6_get_binding_context(struct in6_addr *hoa, struct in6_addr *remote)
{
	struct mipv6_binding_context *ctx;

	list_for_each_entry (ctx, &binding_update_list, entry) {
		if (hoa && in6_addr_compare(bctx_hoa(ctx), hoa) != 0)
			continue;
		if (remote && in6_addr_compare(ctx->destination, remote) != 0)
			continue;

		return ctx;
	}

	return NULL;
}

static int
bctx_bu_timeout(struct mipv6_binding_context *ctx)
{
	if (ctx->refresh_advice)
		return ctx->refresh_advice * 1000;
	else
		return ctx->lifetime * 1000 / 2;
}

static inline int
secs(int input_value)
{
	return (input_value + 500) / 1000;
}

static inline int
ms(int input_value)
{
	return input_value * 1000;
}

static int
bctx_remaining_lifetime(mipv6_binding_context_t *ctx)
{
	if (ctx->flags & MIPV6_BCTX_ACTIVE_REG)
		return secs(timer_remaining_time(&ctx->valid));

	return 0;
}

static void
bctx_bcache_update_with(mipv6_binding_context_t *ctx, mblty_address_t *coa)
{
	if (ctx->flags & MIPV6_BCTX_HOMEREG)
		return;

	kern_bcache_update(bctx_hoa(ctx), ctx->destination, OS_BCE_DIR_LOCAL,
			   coa ? &coa->address : NULL, NULL, NULL);
}

static void
bctx_schedule_transm(struct mipv6_binding_context *ctx, int for_ack)
{
	uint32_t value = bctx_bu_timeout(ctx);

	ctx->flags |= MIPV6_BCTX_SCHEDULED_BU;

	if (for_ack) {
		ctx->flags |= MIPV6_BCTX_WAITING_ACK;
		value = ctx->retry_timeout;
	}

	timer_add(&ctx->trans, value);
}

static void
bctx_update_lifetime(mipv6_binding_context_t *ctx)
{
	int lifetime = ctx->lifetime;

	if (ctx->parent) {
		int p_remain = bctx_remaining_lifetime(ctx->parent);

		if (lifetime > p_remain)
			lifetime = p_remain;
	}

	if (ctx->flags & MIPV6_BCTX_ACTIVE_REG) {
		timer_update(&ctx->valid, ms(lifetime));
	} else {
		timer_add(&ctx->valid, ms(lifetime));
	}

	ctx->flags |= MIPV6_BCTX_ACTIVE_REG;
	ctx->active_lifetime = lifetime;
}

static void
bctx_update_registration(struct mipv6_binding_context *ctx, int lifetime)
{
	int l_remain, l_update, new_l, l_ack;

	debug_assert(ctx->flags & MIPV6_BCTX_ACTIVE_REG,
		     "bctx_update_registration called on inactive state");

	l_remain = timer_remaining_time(&ctx->valid);
	l_update = ms(ctx->active_lifetime);
	l_ack = ms(lifetime);

	new_l = l_remain - (l_update - l_ack);
	if (new_l < 0)
		new_l = 0;

	timer_update(&ctx->valid, new_l);

	bctx_bcache_update_with(ctx, ctx->coa);
}

static void
bctx_cancel_registration(struct mipv6_binding_context *ctx)
{
	if (!(ctx->flags & MIPV6_BCTX_ACTIVE_REG))
		return;

	ctx->flags &= ~MIPV6_BCTX_ACTIVE_REG;
	timer_remove(&ctx->valid);

	bctx_bcache_update_with(ctx, NULL);
}

static void
binding_context_was_acked(struct mipv6_binding_context *ctx, int implicit,
			  int lifetime)
{
	debug_log(4, "binding_context_was_acked(%p, %i).\n", ctx, implicit);

	if (implicit)
		lifetime = ctx->active_lifetime;

	if (ctx->coa != NULL) {
		bctx_update_registration(ctx, lifetime);
		bctx_schedule_transm(ctx, 0);
	} else {
		bctx_cancel_registration(ctx);
	}

	if (!(ctx->flags & MIPV6_BCTX_PENDING_NEW_REG))
		return;

	ctx->flags &= ~MIPV6_BCTX_PENDING_NEW_REG;

	if (ctx->cb_completed_reg)
		ctx->cb_completed_reg(ctx);
}

static void
bctx_cancel_transmissions(struct mipv6_binding_context *ctx)
{
	if (!(ctx->flags & MIPV6_BCTX_SCHEDULED_BU))
		return;

	ctx->flags &= ~MIPV6_BCTX_WAITING_ACK;
	ctx->flags &= ~MIPV6_BCTX_SCHEDULED_BU;

	timer_remove(&ctx->trans);
}

static void
binding_context_reg_was_accepted(struct mipv6_binding_context *ctx,
				 struct ip6_mh_binding_ack *ack, size_t length)
{
	int lifetime = MIPV6_GET_BU_LIFETIME(ntohs(ack->ip6mhba_lifetime));
	size_t optlen = length - sizeof(struct ip6_mh_binding_ack);
	struct ip6_mh_opt_refresh_advice *refadv;
	struct ip6_mh_opt *mopt;

	ctx->refresh_advice = 0;

	for (mopt = mipv6_first_opt(ack + 1, optlen); mopt != NULL;
			mopt = mipv6_next_opt(mopt, &optlen)) {
		if (mopt->ip6mhopt_type == IP6_MHOPT_BREFRESH) {
			int interval;

			refadv = (void *)mopt;
			interval = ntohs(refadv->ip6mora_interval);

			ctx->refresh_advice = MIPV6_GET_BU_LIFETIME(interval);
		}
	}

	debug_assert(ctx->flags & MIPV6_BCTX_WAITING_ACK,
		     "Unexpected acceptance of registration?");

	bctx_cancel_transmissions(ctx);

	binding_context_was_acked(ctx, 0, lifetime);
}

const char *
mipv6_error_description(struct mipv6_binding_context *ctx)
{
	switch (ctx->error.level) {
	case MIPV6_BCTX_ERRLVL_INTERNAL:
		switch (ctx->error.status) {
		case MIPV6_BCTX_ERROR_NOSUPP:
			return "No MIPv6 support";
		}
		break;
	case MIPV6_BCTX_ERRLVL_BERR:
		switch (ctx->error.status) {
		case IP6_MH_BES_UNKNOWN_HOA:
			return "Unknown HoA";
		case IP6_MH_BES_UNKNOWN_MH:
			return "Unknown Mobility header";
		}
		break;
	case MIPV6_BCTX_ERRLVL_BACK:
		return mipv6_ack_status_name(ctx->error.status);
	}

	return "Unknown";
}

static void
bctx_mark_failed(mipv6_binding_context_t *ctx, int err_level, int err_status)
{
	char buf1[INET6_ADDRSTRLEN], buf2[INET6_ADDRSTRLEN];

	if (ctx->flags & MIPV6_BCTX_ACTIVE_REG)
		bctx_cancel_registration(ctx);

	ctx->flags &= ~MIPV6_BCTX_PENDING_NEW_REG;

	ctx->flags |= MIPV6_BCTX_FAILED;
	timer_add(&ctx->valid, MIPV6_RETRY_AFTER_ERROR_TIMEOUT);

	ctx->error.level = err_level;
	ctx->error.status = err_status;

	debug_log(4, "Binding context for (%s, %s) failed with error: %s\n",
		  format_addr(buf1, mblty_get_addr(ctx->hoa)),
		  format_addr(buf2, ctx->destination),
		  mipv6_error_description(ctx));

	if (ctx->cb_update_failed)
		ctx->cb_update_failed(ctx);
}

static void
bctx_clear_failed(struct mipv6_binding_context *ctx)
{
	if (ctx->flags & MIPV6_BCTX_FAILED) {
		ctx->flags &= ~MIPV6_BCTX_FAILED;
		timer_remove(&ctx->valid);
	}
}

static void
bctx_handle_error(struct mipv6_binding_context *ctx, int level, int error)
{
	bctx_cancel_transmissions(ctx);

	if (ctx->flags & MIPV6_BCTX_ACTIVE_REG)
		bctx_cancel_registration(ctx);
	else if (ctx->flags & MIPV6_BCTX_FAILED)
		bctx_clear_failed(ctx);

	bctx_mark_failed(ctx, level, error);
}

static void
binding_context_unrecov_error(struct mipv6_binding_context *ctx, int status)
{
	bctx_handle_error(ctx, MIPV6_BCTX_ERRLVL_BACK, status);
}

static void
bctx_restart_registration(struct mipv6_binding_context *ctx)
{
	bctx_cancel_transmissions(ctx);
	bctx_send_binding_update(ctx);
}

static void
binding_context_handle_error_ack(struct mipv6_binding_context *ctx,
				 struct ip6_mh_binding_ack *msg, int length)
{
	switch (msg->ip6mhba_status) {
	case IP6_MH_BAS_UNSPECIFIED:
	case IP6_MH_BAS_PROHIBIT:
	case IP6_MH_BAS_INSUFFICIENT:
	case IP6_MH_BAS_HA_NOT_SUPPORTED:
	case IP6_MH_BAS_DAD_FAILED:
	case IP6_MH_BAS_REG_NOT_ALLOWED:
		/* unrecoverable error */
		binding_context_unrecov_error(ctx, msg->ip6mhba_status);
		break;

	case IP6_MH_BAS_NOT_HOME_SUBNET:
		/* XXX do prefix discovery */
		break;

	case IP6_MH_BAS_NOT_HA:
		/* XXX do HA discovery */
		break;

	case IP6_MH_BAS_SEQNO_BAD:
		debug_log(3, "Registration failed with Bad Sequence number"
			  " (%u vs. %u). Adjusting sequence number.\n",
			  ctx->sequence, ntohs(msg->ip6mhba_seqno));
		/* the binding ack passed authentication, so we assume
		 * the information may be trusted. */
		/* We adjust our sequence number to the correspondent's
		 * last registed sequence number (the one it replied with). */
		ctx->sequence = ntohs(msg->ip6mhba_seqno);
		/* and then trigger a new BU */
		bctx_restart_registration(ctx);
		break;

	case IP6_MH_BAS_HOME_NI_EXPIRED:
	case IP6_MH_BAS_COA_NI_EXPIRED:
	case IP6_MH_BAS_NI_EXPIRED:
		/* re-trigger RR */
		break;

	default:
		if (msg->ip6mhba_status < 128) {
			/* ignored */
			ctx->stats.back.dscrd++;
		} else {
			binding_context_unrecov_error(ctx,
						      msg->ip6mhba_status);
		}
	}
}

static void
binding_context_handle_expected_ack(struct mipv6_binding_context *ctx,
				    struct ip6_mh_binding_ack *msg, int length)
{
	if ((ctx->sequence != ntohs(msg->ip6mhba_seqno)) &&
	    (msg->ip6mhba_status != IP6_MH_BAS_SEQNO_BAD)) {
		debug_log(3, "Ignoring out of order BU-Ack, got %u expected %u.\n",
			  ctx->sequence, ntohs(msg->ip6mhba_seqno));
		ctx->stats.back.dscrd++;
		return;
	}

	if (msg->ip6mhba_status < 128) {
		/* Binding was accepted */

		if (msg->ip6mhba_status == IP6_MH_BAS_PRFX_DISCOV) {
			/* From RFC 3775
			 *   Additionally, if the Status field value is 1
			 *   (accepted but prefix discovery necessary), the
			 *   mobile node SHOULD send a Mobile Prefix
			 *   Solicitation message to update its information
			 *   about the available prefixes. */

			/* XXX Unimplemented */
		}

		binding_context_reg_was_accepted(ctx, msg, length);
	} else {
		binding_context_handle_error_ack(ctx, msg, length);
	}
}

static int
mipv6_authorize_bu_ack(struct mipv6_binding_context *ctx, struct in6_addr *coa,
		       struct ip6_mh_binding_ack *msg, int length)
{
	if (ctx->auth == NULL || ctx->auth->ops->auth_bu_ack == NULL)
		return 0;

	return ctx->auth->ops->auth_bu_ack(ctx, coa, msg, length);
}

static void
mipv6_bctx_handle_ack(struct mipv6_binding_context *ctx, struct in6_addr *coa,
		      struct ip6_mh_binding_ack *msg, int length)
{
	ctx->stats.back.rx++;

	if (mipv6_authorize_bu_ack(ctx, coa, msg, length) != 0) {
		ctx->stats.back.dscrd++;
		return;
	}

	if (ctx->flags & MIPV6_BCTX_WAITING_ACK)
		binding_context_handle_expected_ack(ctx, msg, length);
	else
		binding_context_handle_error_ack(ctx, msg, length);
}

static void
mipv6_handle_binding_refresh_req(struct mipv6_msgctx *msg)
{
	int expected = sizeof(struct ip6_mh_binding_request);
	struct mipv6_binding_context *ctx;

	if (mipv6_validate_message(msg, expected) < 0)
		return;

	ctx = mipv6_get_binding_context(msg->to, msg->from);
	if (ctx == NULL)
		return;

	ctx->stats.brr.rx++;

	if (!(ctx->flags & MIPV6_BCTX_WAITING_ACK))
		bctx_send_binding_update(ctx);
}

static void
mipv6_handle_binding_ack(struct mipv6_msgctx *msg)
{
	char buf1[INET6_ADDRSTRLEN], buf2[INET6_ADDRSTRLEN],
	     buf3[INET6_ADDRSTRLEN];
	struct ip6_mh_binding_ack *ack = msg->u.raw;
	struct mipv6_binding_context *ctx;

	if (mipv6_validate_message(msg, sizeof(struct ip6_mh_binding_ack)) < 0)
		return;

	debug_log(4, "mipv6_handle_binding_ack(%s, %s, %s, %i bytes)\n",
		  format_addr(buf1, msg->from), format_addr(buf2, msg->to),
		  msg->origdst ? format_addr(buf3, msg->origdst) : NULL,
		  msg->msglen);

	/* We assume the destination address is our HoA. This
	 * is valid as the kernel should process the RT2 HDR
	 * before passing the packet for UPL processing */
	ctx = mipv6_get_binding_context(msg->to, msg->from);
	if (ctx == NULL) {
		debug_log(4, "  Unknown context.\n");
		return;
	}

	mipv6_bctx_handle_ack(ctx, msg->origdst, ack, msg->msglen);
}

static int
mipv6_bctx_sendmsg(struct mipv6_binding_context *bctx,
		   struct mipv6_mh_bld_ctx *msgctx)
{
	struct in6_addr *inddst = NULL;

	if (bctx->reverse)
		inddst = bce_coa(bctx->reverse);

	return mipv6_sendmsg(msgctx, bctx_hoa(bctx), bctx->destination,
			     bctx_coa(bctx), inddst);
}

static void
mipv6_handle_binding_error(struct mipv6_msgctx *msg)
{
	int expected = sizeof(struct ip6_mh_binding_error);
	struct ip6_mh_binding_error *berr = msg->u.raw;
	struct mipv6_binding_context *ctx;

	if (mipv6_validate_message(msg, expected) < 0)
		return;

	ctx = mipv6_get_binding_context(&berr->ip6mhbe_homeaddr, msg->from);
	if (ctx == NULL)
		return;

	ctx->stats.berr.rx++;

	bctx_handle_error(ctx, MIPV6_BCTX_ERRLVL_BERR, berr->ip6mhbe_status);
}

static void
mipv6_handle_prob_in_bu(mipv6_msgctx_t *msgctx)
{
	struct ip6_mh_binding_update *bu = msgctx->u.raw;
	struct mipv6_binding_context *ctx;
	struct in6_addr *hoa = NULL, *coa;

	if (msgctx->msglen < sizeof(struct ip6_mh_binding_update))
		return;

	coa = msgctx->from;
	if (msgctx->hoa == NULL) {
		/* No Home Address destination option in the
		 * visible part of the packet, let's assume it
		 * was transmitted without it */
		hoa = coa;
		coa = NULL;
	}

	ctx = mipv6_get_binding_context(hoa, msgctx->to);
	if (ctx == NULL) {
		char buf1[INET6_ADDRSTRLEN], buf2[INET6_ADDRSTRLEN];
		debug_log(7, "No Binding Context matches the information in "
			  "the ICMPv6 error message (hoa=%s, remote=%s). Old "
			  "state or attack?\n", format_addr(buf1, hoa),
			  format_addr(buf2, msgctx->to));
		return;
	}

	/* CoA mismatch? */
	if (coa == NULL && ctx->coa) {
		debug_log(7, "Ignoring ICMPv6 error message due to CoA mismatch.\n");
		return;
	}

	if ((ctx->flags & MIPV6_BCTX_ACTIVE_REG) ||
	    (ctx->flags & MIPV6_BCTX_WAITING_ACK)) {
		if (ntohs(bu->ip6mhbu_seqno) != ctx->sequence) {
			debug_log(7, "Ignoring ICMPv6 error message due to"
				  "sequence number mismatch.\n");
			return;
		}

		/* destination doesn't understand message */
		bctx_handle_error(ctx, MIPV6_BCTX_ERRLVL_INTERNAL,
				  MIPV6_BCTX_ERROR_NOSUPP);
	}
}

static inline int
bctx_is_expired(struct mipv6_binding_context *ctx)
{
	return ctx->flags & MIPV6_BCTX_EXPIRED;
}

void
bctx_send_binding_update(struct mipv6_binding_context *ctx)
{
	char buf1[INET6_ADDRSTRLEN], buf2[INET6_ADDRSTRLEN];
	struct ip6_mh_binding_update *bu;
	struct mipv6_mh_bld_ctx bu_ctx;
	char buf3[INET6_ADDRSTRLEN];
	int tx_failed = 0;

	bu = mipv6_mh_start(&bu_ctx, sizeof(struct ip6_mh_binding_update));

	if (ctx->flags & (MIPV6_BCTX_NO_SEND_BU | MIPV6_BCTX_FAILED))
		return;

	debug_log(2, "Sending Binding Update to %s from %s via %s.\n",
		  format_addr(buf1, ctx->destination), format_addr(buf2,
		  bctx_hoa(ctx)), format_addr(buf3, bctx_coa(ctx)));

	/* still waiting for ACK? then this is a retransmit */
	if (ctx->flags & MIPV6_BCTX_WAITING_ACK) {
		ctx->retry_timeout = MIN(ctx->retry_timeout * 2,
					 MIPV6_MAX_BINDACK_TIMEOUT);
	} else {
		ctx->retry_timeout = MIPV6_INITIAL_BINDACK_TIMEOUT;

		if ( (ctx->flags & MIPV6_BCTX_HOMEREG) &&
		    !(ctx->flags & MIPV6_BCTX_ACTIVE_REG))
			ctx->retry_timeout = MIPV6_INITIAL_BINDACK_TIMEOUT_FIRST_REG;
	}

	/* From RFC 3775
	 *   Retransmitted Binding Updates MUST use a Sequence Number value
	 *   greater than that used for the previous transmission of this
	 *   Binding Update. */
	ctx->sequence++;
	bu->ip6mhbu_seqno = htons(ctx->sequence);

	if (ctx->coa) {
		bctx_update_lifetime(ctx);
		bu->ip6mhbu_lifetime =
			htons(MIPV6_BU_LIFETIME(ctx->active_lifetime));
	} else {
		bu->ip6mhbu_lifetime = 0;
	}

	if (ctx->flags & MIPV6_BCTX_WANT_ACK)
		bu->ip6mhbu_flags |= IP6_MH_BU_ACK;

	if (ctx->flags & MIPV6_BCTX_HOMEREG)
		bu->ip6mhbu_flags |= IP6_MH_BU_HOME;

	if (ctx->coa && (ctx->flags & MIPV6_BCTX_USE_ALT_COA)) {
		struct ip6_mh_opt_altcoa *altcoa;

		altcoa = mipv6_mh_add_opt(&bu_ctx, 8, 6, IP6_MHOPT_ALTCOA,
					  sizeof(struct ip6_mh_opt_altcoa));

		in6_addr_copy(&altcoa->ip6moa_addr, bctx_coa(ctx));
	}

	if (ctx->flags & MIPV6_BCTX_HAS_NAI) {
		struct ip6_mh_opt_x_mn_ident *mni;
		int nai_len = strlen(ctx->nai);

		mni = mipv6_mh_add_opt(&bu_ctx, 0, 0, IP6_MHOPT_X_MN_IDENT,
				       sizeof(struct ip6_mh_opt_x_mn_ident)
				       + nai_len);
		mni->ip6moxmi_subtype = IP6_MH_X_MNI_NAI;

		memcpy(mni + 1, ctx->nai, nai_len);
	}

	bu->ip6mhbu_flags = htons(bu->ip6mhbu_flags);

	if (ctx->auth && ctx->auth->ops->auth_bu) {
		ctx->auth->ops->auth_bu(ctx, &bu_ctx);

		debug_assert((bu_ctx.length % 8) == 0,
			     "Auth method didn't properly align BU");
	} else {
		/* align header to 8n */
		mipv6_mh_pad(&bu_ctx, 8, 0);
	}

	mipv6_build_header(bu_ctx.h.mh, bu_ctx.length, IP6_MH_TYPE_BU);

	if (mipv6_bctx_sendmsg(ctx, &bu_ctx) < 0)
		tx_failed = 1;

	if (!tx_failed) {
		ctx->stats.bu.tx++;
		ctx->ts_bu_last_sent = support_get_sys_timestamp();
	} else
		ctx->stats.bu.failed++;

	/* If sendmsg failed, we'll program a retransmission */

	if (!bctx_is_expired(ctx)) {
		if (tx_failed || (ctx->flags & MIPV6_BCTX_WANT_ACK))
			bctx_schedule_transm(ctx, 1);
		else
			binding_context_was_acked(ctx, 1, 0);
	}
}

static void
mipv6_handle_bctx_valid_timer(suptimer_t *tmr, void *arg)
{
	struct mipv6_binding_context *ctx = arg;

	/* whatever current state -- active or failed -- timed out */

	if (ctx->flags & MIPV6_BCTX_ACTIVE_REG) {
		ctx->flags &= ~MIPV6_BCTX_ACTIVE_REG;
		bctx_bcache_update_with(ctx, NULL);
	} else if (ctx->flags & MIPV6_BCTX_FAILED) {
		ctx->flags &= ~MIPV6_BCTX_FAILED;
		bctx_send_binding_update(ctx);
	}
}

static void
mipv6_handle_bctx_trasm_timer(suptimer_t *tmr, void *arg)
{
	bctx_send_binding_update((struct mipv6_binding_context *)arg);
}

static void
mipv6_bctx_reset_stats(struct mipv6_binding_context *ctx)
{
	memset(&ctx->stats, 0, sizeof(ctx->stats));
}

void
mipv6_init_binding_context(struct mipv6_binding_context *ctx,
			   mblty_network_address_t *hoa, struct in6_addr *d)
{
	ctx->parent = NULL;
	ctx->hoa = hoa;
	ctx->destination = d;
	ctx->sequence = mipv6_generate_rand_uint16();
	ctx->lifetime = 180;
	ctx->active_lifetime = 0;
	ctx->refresh_advice = 0;
	ctx->flags = 0;
	ctx->coa = NULL;
	ctx->owner = NULL;
	ctx->ts_bu_last_sent = 0;

	timer_init_with(&ctx->valid, "bctx valid timer",
			mipv6_handle_bctx_valid_timer, ctx);
	timer_init_with(&ctx->trans, "bctx transm timer",
			mipv6_handle_bctx_trasm_timer, ctx);

	ctx->retry_timeout = 0;
	ctx->error.level = 0;
	ctx->error.status = 0;
	mipv6_bctx_reset_stats(ctx);

	ctx->cb_update_failed = NULL;
	ctx->cb_completed_reg = NULL;

	ctx->auth = NULL;

	ctx->nai = NULL;

	list_add_tail(&ctx->entry, &binding_update_list);

	ctx->reverse = mipv6_bcache_get_entry(d, bctx_hoa(ctx));
	if (ctx->reverse)
		ctx->reverse->reverse = ctx;
}

void
mipv6_remove_binding_context(struct mipv6_binding_context *ctx)
{
	int hadreg = (ctx->flags & MIPV6_BCTX_ACTIVE_REG);
	int hadfailed = (ctx->flags & MIPV6_BCTX_FAILED);

	if (ctx->reverse)
		ctx->reverse->reverse = NULL;

	mipv6_clear_binding(ctx);

	if (hadreg && !hadfailed && bctx_is_expired(ctx))
		bctx_send_binding_update(ctx);

	if (ctx->auth) {
		mipv6_auth_data_release(ctx->auth);
		ctx->auth = NULL;
	}

	list_del(&ctx->entry);
}

void
mipv6_update_binding(mipv6_binding_context_t *ctx, mblty_address_t *new_coa)
{
	mblty_address_t *old = ctx->coa;

	if (old == new_coa)
		return;

	mblty_put_address(old);
	ctx->coa = mblty_get_address(new_coa);

	ctx->flags |= MIPV6_BCTX_PENDING_NEW_REG;

	bctx_cancel_transmissions(ctx);
	bctx_clear_failed(ctx);

	bctx_send_binding_update(ctx);
}

void
mipv6_clear_binding(struct mipv6_binding_context *ctx)
{
	mblty_put_address(ctx->coa);
	ctx->coa = NULL;
	bctx_cancel_transmissions(ctx);
	ctx->flags &= ~MIPV6_BCTX_PENDING_NEW_REG;
	bctx_clear_failed(ctx);
	mipv6_reset_binding(ctx);
}

void
mipv6_reset_binding(struct mipv6_binding_context *ctx)
{
	if (ctx->flags & MIPV6_BCTX_ACTIVE_REG)
		bctx_cancel_registration(ctx);
}

void
mipv6_binding_force_update(struct mipv6_binding_context *ctx)
{
	bctx_send_binding_update(ctx);
}

int
mipv6_foreach_binding_context(int (*cb)(mipv6_binding_context_t *, void *),
			      void *cb_arg)
{
	struct mipv6_binding_context *bctx, *tmp;
	int res;

	list_for_each_entry_safe (bctx, tmp, &binding_update_list, entry) {
		if ((res = cb(bctx, cb_arg)) != 0)
			break;
	}

	return res;
}

static void
proto_mn_register_handlers(int on)
{
	mipv6_proto_register_handler(IP6_MH_TYPE_BRR,
				     mipv6_handle_binding_refresh_req, on);
	mipv6_proto_register_handler(IP6_MH_TYPE_BACK,
				     mipv6_handle_binding_ack, on);
	mipv6_proto_register_handler(IP6_MH_TYPE_BERROR,
				     mipv6_handle_binding_error, on);
	mipv6_proto_register_prob_handler(IP6_MH_TYPE_BU,
					  mipv6_handle_prob_in_bu, on);
}

static void
mipv6_proto_mn_shutdown()
{
	proto_mn_register_handlers(0);
}

static struct mblty_shutdown_entry proto_mn_shutdown = {
	.handler = mipv6_proto_mn_shutdown,
};

void
mipv6_proto_mn_init()
{
	proto_mn_register_handlers(1);
	mblty_register_shutdown(&proto_mn_shutdown);
}

