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

#include <stdio.h>

#include <mblty/ndisc.h>
#include <mblty/icmpv6.h>
#include <mblty/interface.h>
#include <mblty/base-support.h>

static ndisc_conf_t *ndisc_conf = NULL;

struct nd_pend_sol {
	int refcount;
	mblty_interface_t *intf;
	struct in6_addr target, dest;

#define NDISC_PENDSOL_RTX_RUNNING	0x0001
	uint32_t flags;

	int rtx_count, rtx_interval;
	suptimer_t rtx_timer;

	void (*result)(struct nd_pend_sol *, ndisc_handler_context_t *,
		       int result);
	void *param;

	struct list_entry entry;
};

struct nd_std_pend_sol {
	struct nd_pend_sol sol;
	ndisc_solicitation_cb_t cb;
};

struct nd_nud_pend_sol {
	struct nd_pend_sol sol;
	ndisc_nud_reply_cb_t cb;
};

static void nd_handle_neigh_sol(ndisc_handler_context_t *);
static void nd_handle_neigh_adv(ndisc_handler_context_t *);

static void nd_pend_decref(struct nd_pend_sol *);
static void ndisc_perform_dad(mblty_os_intf_t *osh, struct in6_addr *target,
			      ndisc_solicitation_cb_t cb, void *cb_arg);

static ndisc_address_record_t *ndisc_get_record(mblty_os_intf_t *,
						struct in6_addr *);
static void ndisc_addr_failed_dad(ndisc_address_record_t *);

static LIST_DEF(records);
static LIST_DEF(pending);

static const int nd_hdr_size[] = {
	sizeof(struct nd_router_solicit),   /* ND_ROUTER_SOLICIT */
	sizeof(struct nd_router_advert),    /* ND_ROUTER_ADVERT */
	sizeof(struct nd_neighbor_solicit), /* ND_NEIGHBOR_SOLICIT */
	sizeof(struct nd_neighbor_advert),  /* ND_NEIGHBOR_ADVERT */
	sizeof(struct nd_redirect),         /* ND_REDIRECT */
};

static struct list_entry nd_msg_handlers[ND_REDIRECT - ND_ROUTER_SOLICIT + 1];

static ndisc_handler_t nd_neisol_handler = {
	.event = nd_handle_neigh_sol,
};

static ndisc_handler_t nd_neiadv_handler = {
	.event = nd_handle_neigh_adv,
};

int
ndisc_prepare_lladdr_opt(int type, uint8_t *ptr, int len, mblty_os_intf_t *osh)
{
	int optlen = mblty_os_intf_get_address(osh, ptr + 2, len - 2);

	if (optlen < 0)
		return -1;

	optlen += 2;

	if (optlen % 8)
		optlen += 8 - (optlen % 8);

	ptr[0] = type;
	ptr[1] = optlen / 8;

	return optlen;
}

static void
in6addr_all_nodes_init(struct in6_addr *addr)
{
	memset(addr, 0, sizeof(struct in6_addr));
	addr->s6_addr[ 0] = 0xff;
	addr->s6_addr[ 1] = 0x02;
	addr->s6_addr[15] = 0x01;
}

static int
ndisc_send_na(ndisc_address_record_t *rec, struct in6_addr *requester,
	      int override)
{
	struct in6_addr to, *target = &rec->address->address;
	struct {
		struct nd_neighbor_advert h;
		uint8_t opt[MBLTY_NEIGH_LLADDR_OPT_MAXSIZE];
	} nei_adv;
	int advlen;

	memset(&nei_adv, 0, sizeof(nei_adv));

	nei_adv.h.nd_na_type = ND_NEIGHBOR_ADVERT;
	if (override)
		nei_adv.h.nd_na_flags_reserved = ND_NA_FLAG_OVERRIDE;
	in6_addr_copy(&nei_adv.h.nd_na_target, target);

	advlen = ndisc_prepare_lladdr_opt(ND_OPT_TARGET_LINKADDR, nei_adv.opt,
					   sizeof(nei_adv.opt), rec->intf->osh);
	if (advlen < 0)
		return -1;

	advlen += sizeof(struct nd_neighbor_advert);

	if (requester) {
		nei_adv.h.nd_na_flags_reserved |= ND_NA_FLAG_SOLICITED;
		in6_addr_copy(&to, requester);
	} else {
		/* all ipv6 nodes mc group */
		in6addr_all_nodes_init(&to);
	}

	return icmpv6_send(&to, target, rec->intf->osh, 255,
			   &nei_adv.h.nd_na_hdr, advlen);
}

static void
ndisc_reply_neigh_solicit(ndisc_handler_context_t *ctx,
			  ndisc_address_record_t *rec)
{
	uint8_t *lladdr = NULL;
	int addrlen = -1;

	while (ndisc_handctx_next_opt(ctx)) {
		if (ctx->opt.hdr == NULL)
			return;

		if (ctx->opt.hdr->nd_opt_type == ND_OPT_SOURCE_LINKADDR) {
			if (lladdr)
				return;
			lladdr = ctx->opt.raw + 2;
			addrlen = ctx->opt.hdr->nd_opt_len * 8 - 2;
		}
	}

	if (lladdr) {
		mblty_os_intf_neigh_update(ctx->iif, ctx->source, lladdr,
					   addrlen);
	}

	if (ndisc_send_na(rec, IN6_IS_ADDR_UNSPECIFIED(ctx->source) ?
			  NULL : ctx->source, 1) < 0) {
		debug_log(1, "Failed to reply to neighbor solicitation.\n");
	}
}

static void
nd_handle_neigh_sol(ndisc_handler_context_t *ctx)
{
	char buf1[INET6_ADDRSTRLEN], buf2[INET6_ADDRSTRLEN], desc[64];
	struct nd_neighbor_solicit *solicit = ctx->hdr.neisol;
	ndisc_address_record_t *rec;

	debug_log(7, "mblty_neigh_solicit(%s, %s)\n",
		  format_addr(buf1, ctx->source),
		  format_addr(buf2, &solicit->nd_ns_target));

	rec = ndisc_get_record(ctx->iif, &solicit->nd_ns_target);
	if (rec) {
		debug_log(4, "%s is asking for %s in %s.\n",
			  format_addr(buf1, ctx->source),
			  format_addr(buf2, &solicit->nd_ns_target),
			  mblty_os_intf_desc(rec->intf->osh, 1, desc,
					     sizeof(desc)));

		if (rec->flags & NDISC_ADDRREC_F_READY)
			ndisc_reply_neigh_solicit(ctx, rec);
		else if (rec->flags & NDISC_ADDRREC_F_PENDING_DAD)
			ndisc_addr_failed_dad(rec);
	} else {
		debug_log(10, "Didn't handle this Neigh Solicitation\n");
	}
}

static ndisc_address_record_t *
ndisc_get_record(mblty_os_intf_t *osh, struct in6_addr *address)
{
	ndisc_address_record_t *rec;

	list_for_each_entry (rec, &records, entry) {
		if (rec->intf->osh == osh &&
		    in6_addr_compare(&rec->address->address, address) == 0)
			return rec;
	}

	return NULL;
}

int
ndisc_addr_register(ndisc_address_record_t *rec, mblty_interface_t *intf,
		    mblty_address_t *address, ndisc_address_ops_t *ops)
{
	debug_assert(rec && intf && address,
		     "Invalid arguments to ndisc_addr_register");

	if (ndisc_get_record(intf->osh, &address->address))
		return -1;

	rec->address = mblty_get_address(address);
	rec->intf = mblty_grab_interface(intf);
	rec->ops = ops;
	rec->flags = 0;

	list_add_tail(&rec->entry, &records);

	return 0;
}

static int
ndisc_announce_address(ndisc_address_record_t *rec)
{
	return ndisc_send_na(rec, NULL, 1);
}

static void
ndisc_addr_finished_dad(ndisc_address_record_t *rec)
{
	rec->flags |= NDISC_ADDRREC_F_READY;

	if (rec->ops && rec->ops->claimed)
		rec->ops->claimed(rec);

	if (rec->flags & NDISC_ADDRREC_F_NOISY)
		ndisc_announce_address(rec);
}

static void
ndisc_build_ns_mcgroup(struct in6_addr *mcgroup, struct in6_addr *addr)
{
	in6_addr_copy(mcgroup, &in6addr_any);

	mcgroup->s6_addr[ 0] = 0xff;
	mcgroup->s6_addr[ 1] = 0x02;
	mcgroup->s6_addr[11] = 0x01;
	mcgroup->s6_addr[12] = 0xff;
	mcgroup->s6_addr[13] = addr->s6_addr[13];
	mcgroup->s6_addr[14] = addr->s6_addr[14];
	mcgroup->s6_addr[15] = addr->s6_addr[15];
}

static void
ndisc_addr_join_ns_mc_group(ndisc_address_record_t *rec, int on)
{
	struct in6_addr mcaddr;

	ndisc_build_ns_mcgroup(&mcaddr, &rec->address->address);

	if (on) {
		if (rec->flags & NDISC_ADDRREC_F_JOINEDSOL)
			return;

		if (icmpv6_join_mc(rec->intf->osh, &mcaddr) == 0)
			rec->flags |= NDISC_ADDRREC_F_JOINEDSOL;
	} else if (rec->flags & NDISC_ADDRREC_F_JOINEDSOL) {
		icmpv6_leave_mc(rec->intf->osh, &mcaddr);
		rec->flags &= ~NDISC_ADDRREC_F_JOINEDSOL;
	}
}

static void
ndisc_addr_failed_dad(ndisc_address_record_t *rec)
{
	rec->flags &= ~NDISC_ADDRREC_F_READY;

	if (rec->flags & NDISC_ADDRREC_F_PENDING_DAD)
		ndisc_cancel_neigh_solicit(rec);

	ndisc_addr_join_ns_mc_group(rec, 0);

	if (rec->ops && rec->ops->dad_failed)
		rec->ops->dad_failed(rec);
}

static void
ndisc_finished_dad_cb(ndisc_handler_context_t *ctx, int result, void *param)
{
	ndisc_address_record_t *rec = param;

	rec->flags &= ~NDISC_ADDRREC_F_PENDING_DAD;

	if (result == MBLTY_NEIGH_SOLICIT_EXPIRED)
		ndisc_addr_finished_dad(rec);
	else
		ndisc_addr_failed_dad(rec);
}

static void
ndisc_addr_initiate_dad(ndisc_address_record_t *rec)
{
	rec->flags |= NDISC_ADDRREC_F_PENDING_DAD;

	ndisc_perform_dad(rec->intf->osh, &rec->address->address,
			  ndisc_finished_dad_cb, rec);
}

void
ndisc_addr_proceed(ndisc_address_record_t *rec)
{
	ndisc_addr_join_ns_mc_group(rec, 1);

	if (rec->flags & NDISC_ADDRREC_F_NEEDS_DAD)
		ndisc_addr_initiate_dad(rec);
	else
		ndisc_addr_finished_dad(rec);
}

void
ndisc_addr_reset(ndisc_address_record_t *rec)
{
	rec->flags &= ~NDISC_ADDRREC_F_READY;

	if (rec->flags & NDISC_ADDRREC_F_PENDING_DAD) {
		ndisc_cancel_neigh_solicit(rec);
		rec->flags &= ~NDISC_ADDRREC_F_PENDING_DAD;
	}

	ndisc_addr_join_ns_mc_group(rec, 0);
}

void
ndisc_addr_unregister(ndisc_address_record_t *rec)
{
	ndisc_addr_reset(rec);
	list_del(&rec->entry);

	mblty_put_address(rec->address);
	mblty_put_interface(rec->intf);
}

static void
join_all_nodes(mblty_interface_t *intf, int join)
{
	struct in6_addr in6addr_allnodes;
	in6addr_all_nodes_init(&in6addr_allnodes);

	if (join)
		icmpv6_join_mc(intf->osh, &in6addr_allnodes);
	else
		icmpv6_leave_mc(intf->osh, &in6addr_allnodes);
}

static void
nd_pend_link(struct nd_pend_sol *sol)
{
	if (list_empty(&pending))
		join_all_nodes(sol->intf, 1);
	list_add_tail(&sol->entry, &pending);
}

static void
nd_pend_unlink(struct nd_pend_sol *sol)
{
	list_del(&sol->entry);
	if (list_empty(&pending))
		join_all_nodes(sol->intf, 0);
}

static void
nd_pend_free(struct nd_pend_sol *sol)
{
	if (sol->flags & NDISC_PENDSOL_RTX_RUNNING) {
		timer_remove(&sol->rtx_timer);
		sol->flags &= ~NDISC_PENDSOL_RTX_RUNNING;
	}

	nd_pend_unlink(sol);
	mblty_put_interface(sol->intf);
	free_object(sol);
}

static void
nd_pend_decref(struct nd_pend_sol *sol)
{
	sol->refcount--;

	if (sol->refcount == 0)
		nd_pend_free(sol);
}

static ndisc_handler_context_t *
ndisc_handctx_clone(ndisc_handler_context_t *t, ndisc_handler_context_t *src)
{
	t->iif = src->iif;
	t->source = src->source;
	t->dest = src->dest;

	t->hdr.icmp6 = src->hdr.icmp6;
	t->opt.hdr = src->opt.hdr;

	t->length = src->length;
	t->optlen = src->optlen;
	t->next_opt = src->next_opt;

	return t;
}

static struct nd_opt_hdr *
ndisc_find_opt(ndisc_handler_context_t *ctx, int type)
{
	while (ndisc_handctx_next_opt(ctx)) {
		if (ctx->opt.hdr == NULL)
			break;
		else if (ctx->opt.hdr->nd_opt_type == type)
			return ctx->opt.hdr;
	}

	return NULL;
}

static void
nd_pend_call(struct nd_pend_sol *sol, ndisc_handler_context_t *ctx,
	     int result)
{
	sol->result(sol, ctx, result);
	nd_pend_decref(sol);
}

static void
nd_pend_call_std(struct nd_pend_sol *sol, ndisc_handler_context_t *ctx,
		 int result)
{
	struct nd_std_pend_sol *std =
		container_of(sol, struct nd_std_pend_sol, sol);

	std->cb(ctx, result, sol->param);
}

static void
nd_pend_call_nud(struct nd_pend_sol *sol, ndisc_handler_context_t *ctx,
		 int result)
{
	ndisc_nud_result_t res = {
		.result = NDISC_NUD_RES_FAILED,
		.flags = 0,
		.linkaddr_opt = NULL,
	};
	struct nd_nud_pend_sol *std =
		container_of(sol, struct nd_nud_pend_sol, sol);

	if (result == MBLTY_NEIGH_SOLICIT_OK) {
		res.result = NDISC_NUD_RES_REACHABLE;
		res.flags = ctx->hdr.neiadv->nd_na_flags_reserved;
		res.linkaddr_opt = ndisc_find_opt(ctx, ND_OPT_SOURCE_LINKADDR);
	} else if (result == MBLTY_NEIGH_SOLICIT_EXPIRED) {
		res.result = NDISC_NUD_RES_EXPIRED;
	}

	std->cb(&res, sol->param);
}

static void
nd_handle_neigh_adv(ndisc_handler_context_t *ctx)
{
	char buf1[INET6_ADDRSTRLEN], buf2[INET6_ADDRSTRLEN];
	ndisc_handler_context_t tmpctx;
	struct nd_pend_sol *sol, *tmp;
	struct in6_addr *target;

	debug_log(6, "nd_handle_neigh_adv(%s from %s)\n",
		  format_addr(buf1, &ctx->hdr.neiadv->nd_na_target),
		  format_addr(buf2, ctx->source));

	target = &ctx->hdr.neiadv->nd_na_target;

	list_for_each_entry_safe (sol, tmp, &pending, entry) {
		if (in6_addr_compare(&sol->target, target) == 0) {
			sol->refcount++;
			ndisc_handctx_clone(&tmpctx, ctx);
			nd_pend_call(sol, &tmpctx, MBLTY_NEIGH_SOLICIT_OK);
		}
	}

	list_for_each_entry_safe (sol, tmp, &pending, entry) {
		if (in6_addr_compare(&sol->target, target) == 0)
			nd_pend_decref(sol);
	}
}

static void
nd_pend_start_rtx(struct nd_pend_sol *sol)
{
	sol->flags |= NDISC_PENDSOL_RTX_RUNNING;
	timer_add(&sol->rtx_timer, sol->rtx_interval);
}

static int
nd_pend_perform(struct nd_pend_sol *sol)
{
	struct in6_addr from;
	struct {
		struct nd_neighbor_solicit hdr;
		uint8_t opt[MBLTY_NEIGH_LLADDR_OPT_MAXSIZE];
	} ns;
	int ns_len = 0;

	if (mblty_linklocal_for(sol->intf, &sol->dest, &from) < 0)
		in6_addr_copy(&from, &in6addr_any);

	if (!IN6_IS_ADDR_UNSPECIFIED(&from)) {
		ns_len = ndisc_prepare_lladdr_opt(ND_OPT_SOURCE_LINKADDR,
						  ns.opt, sizeof(ns.opt),
						  sol->intf->osh);
		if (ns_len < 0)
			ns_len = 0;
	}

	ns_len += sizeof(struct nd_neighbor_solicit);

	memset(&ns.hdr, 0, sizeof(ns.hdr));
	ns.hdr.nd_ns_type = ND_NEIGHBOR_SOLICIT;
	in6_addr_copy(&ns.hdr.nd_ns_target, &sol->target);

	if (icmpv6_send(&sol->dest, &from, sol->intf->osh, 255,
			&ns.hdr.nd_ns_hdr, ns_len) < 0)
		return -1;

	nd_pend_start_rtx(sol);
	return 0;
}

static void
nd_pend_continue(struct nd_pend_sol *sol)
{
	/* called from init method, or from timer context
	 * so timer is not running */
	sol->flags &= ~NDISC_PENDSOL_RTX_RUNNING;

	if (sol->rtx_count > 0) {
		sol->rtx_count--;

		if (nd_pend_perform(sol) < 0)
			nd_pend_call(sol, NULL, MBLTY_NEIGH_SOLICIT_FAILED);
	} else {
		nd_pend_call(sol, NULL, MBLTY_NEIGH_SOLICIT_EXPIRED);
	}
}

static void
nd_pend_expired(suptimer_t *tmr, void *param)
{
	nd_pend_continue(container_of(tmr, struct nd_pend_sol, rtx_timer));
}

static void
ndisc_perform_solicit(struct nd_pend_sol *sol, mblty_os_intf_t *osh,
		      struct in6_addr *target, int solicited,
		      struct ndisc_ns_conf *nsc, void *param)
{
	char buf1[INET6_ADDRSTRLEN];

	sol->refcount = 1;
	in6_addr_copy(&sol->target, target);
	sol->intf = mblty_get_interface(osh);
	debug_assert(sol->intf, "Request on non-interface?");

	if (solicited)
		in6_addr_copy(&sol->dest, target);
	else
		ndisc_build_ns_mcgroup(&sol->dest, target);

	sol->param = param;
	sol->rtx_count = nsc->count;
	sol->rtx_interval = nsc->interval;
	sol->flags = 0;
	timer_init_with(&sol->rtx_timer, "nd rtx timer",
			nd_pend_expired, NULL);

	nd_pend_link(sol);

	debug_log(4, "Doing %sneighbor solicitation for target %s.\n",
		  solicited ? "solicited " : "", format_addr(buf1, target));

	nd_pend_continue(sol);
}

void
ndisc_do_neigh_solicit(mblty_os_intf_t *osh, struct in6_addr *target,
		       ndisc_solicitation_cb_t cb, void *prm)
{
	struct nd_std_pend_sol *std = allocate_object(struct nd_std_pend_sol);

	if (std == NULL) {
		cb(NULL, MBLTY_NEIGH_SOLICIT_FAILED, prm);
		return;
	}

	std->sol.result = nd_pend_call_std;
	std->cb = cb;

	ndisc_perform_solicit(&std->sol, osh, target, 0, &ndisc_conf->ns, prm);
}

static void
ndisc_perform_dad(mblty_os_intf_t *osh, struct in6_addr *target,
		  ndisc_solicitation_cb_t cb, void *cb_arg)
{
	struct nd_std_pend_sol *std = allocate_object(struct nd_std_pend_sol);

	if (std == NULL) {
		cb(NULL, MBLTY_NEIGH_SOLICIT_FAILED, cb_arg);
		return;
	}

	std->sol.result = nd_pend_call_std;
	std->cb = cb;

	ndisc_perform_solicit(&std->sol, osh, target, 0, &ndisc_conf->dad,
			      cb_arg);
}

void
ndisc_perform_nud(mblty_os_intf_t *intf, struct in6_addr *target,
		  ndisc_nud_reply_cb_t cb, void *param)
{
	struct nd_nud_pend_sol *nud = allocate_object(struct nd_nud_pend_sol);

	if (nud == NULL) {
		ndisc_nud_result_t res = {
			.result = NDISC_NUD_RES_FAILED,
			.flags = 0,
			.linkaddr_opt = NULL,
		};

		cb(&res, param);
		return;
	}

	nud->sol.result = nd_pend_call_nud;
	nud->cb = cb;

	ndisc_perform_solicit(&nud->sol, intf, target, 1, &ndisc_conf->nud,
			      param);
}

static void
nd_pend_cancel(void *param)
{
	struct nd_pend_sol *sol, *tmp;

	list_for_each_entry_safe (sol, tmp, &pending, entry) {
		if (sol->param == param)
			nd_pend_decref(sol);
	}
}

void
ndisc_cancel_neigh_solicit(void *cb_arg)
{
	nd_pend_cancel(cb_arg);
}

void
ndisc_cancel_nud(ndisc_nud_reply_cb_t cb, void *param)
{
	nd_pend_cancel(param);
}

static struct list_entry *
nd_msg_handler_for_type(int type)
{
	if (type < ND_ROUTER_SOLICIT || type > ND_REDIRECT)
		return NULL;

	return &nd_msg_handlers[type - ND_ROUTER_SOLICIT];
}

static int
ndisc_reg_handler(int type, ndisc_handler_t *handler, int on)
{
	struct list_entry *list;

	list = nd_msg_handler_for_type(type);
	if (list == NULL)
		return -1;

	if (on)
		list_add_tail(&handler->entry, list);
	else
		list_del(&handler->entry);

	return 0;
}

int
ndisc_register_handler(int type, ndisc_handler_t *handler)
{
	return ndisc_reg_handler(type, handler, 1);
}

int
ndisc_unregister_handler(int type, ndisc_handler_t *handler)
{
	return ndisc_reg_handler(type, handler, 0);
}

int
ndisc_handctx_next_opt(ndisc_handler_context_t *ctx)
{
	int optlen;

	if (ctx->optlen == 0)
		return 0;

	if (ctx->optlen < 2) {
		ctx->opt.hdr = NULL;
		return -1;
	}

	ctx->opt.raw = ctx->next_opt;

	optlen = ctx->opt.hdr->nd_opt_len * 8;
	if (optlen > ctx->optlen) {
		ctx->opt.hdr = NULL;
		return -1;
	}

	ctx->next_opt += optlen;
	ctx->optlen   -= optlen;

	return 1;
}

static int
ndisc_handctx_check_opts_priv(ndisc_handler_context_t *ctx)
{
	while (ndisc_handctx_next_opt(ctx)) {
		if (ctx->opt.hdr == NULL)
			return -1;
	}

	return 0;
}

int
ndisc_handctx_check_opts(ndisc_handler_context_t *ctx)
{
	int optlen, res;
	uint8_t *opt;

	opt = ctx->next_opt;
	optlen = ctx->optlen;

	res = ndisc_handctx_check_opts_priv(ctx);

	ctx->next_opt = opt;
	ctx->optlen = optlen;

	return res;
}

static void
nd_handle_msg(struct icmp6_hdr *hdr, int length, supsocket_rxparm_t *rxp)
{
	ndisc_handler_t *handler, *tmp;
	ndisc_handler_context_t ctx;
	struct list_entry *list;
	int hdrlen;

	list = nd_msg_handler_for_type(hdr->icmp6_type);
	if (list == NULL)
		return;

	hdrlen = nd_hdr_size[hdr->icmp6_type - ND_ROUTER_SOLICIT];
	if (length < hdrlen)
		return;

	ctx.iif = rxp->intf;
	ctx.source = rxp->src;
	ctx.dest = rxp->dst;

	ctx.hdr.icmp6 = hdr;
	ctx.length = length;

	list_for_each_entry_safe (handler, tmp, list, entry) {
		ctx.next_opt = ctx.hdr.raw + hdrlen;
		ctx.optlen = length - hdrlen;

		handler->event(&ctx);
	}
}

static void ndisc_shutdown();
static struct mblty_shutdown_entry shutdown_entry = {
	.handler = ndisc_shutdown,
};

void
ndisc_init(ndisc_conf_t *conf)
{
	int i;

	ndisc_conf = conf;

	for (i = ND_ROUTER_SOLICIT; i <= ND_REDIRECT; i++)
		list_init(&nd_msg_handlers[i - ND_ROUTER_SOLICIT]);

	icmpv6_register_handler(ND_ROUTER_SOLICIT, nd_handle_msg, 1);
	icmpv6_register_handler(ND_ROUTER_ADVERT, nd_handle_msg, 1);
	icmpv6_register_handler(ND_NEIGHBOR_SOLICIT, nd_handle_msg, 1);
	icmpv6_register_handler(ND_NEIGHBOR_ADVERT, nd_handle_msg, 1);
	icmpv6_register_handler(ND_REDIRECT, nd_handle_msg, 1);

	ndisc_register_handler(ND_NEIGHBOR_SOLICIT, &nd_neisol_handler);
	ndisc_register_handler(ND_NEIGHBOR_ADVERT, &nd_neiadv_handler);

	mblty_register_shutdown(&shutdown_entry);
}

static void
ndisc_shutdown()
{
	ndisc_unregister_handler(ND_NEIGHBOR_SOLICIT, &nd_neisol_handler);
	ndisc_unregister_handler(ND_NEIGHBOR_ADVERT, &nd_neiadv_handler);

	icmpv6_register_handler(ND_ROUTER_SOLICIT, nd_handle_msg, 0);
	icmpv6_register_handler(ND_ROUTER_ADVERT, nd_handle_msg, 0);
	icmpv6_register_handler(ND_NEIGHBOR_SOLICIT, nd_handle_msg, 0);
	icmpv6_register_handler(ND_NEIGHBOR_ADVERT, nd_handle_msg, 0);
	icmpv6_register_handler(ND_REDIRECT, nd_handle_msg, 0);

	ndisc_conf = NULL;
}

