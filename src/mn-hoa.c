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

#include <mblty/ndisc.h>
#include <mblty/icmpv6.h>
#include <mblty/address.h>
#include <mblty/interface.h>
#include <mblty/base-support.h>

#include <mipv6/os.h>
#include <mipv6/mn-hoa.h>

#define DEF_ROUTE_METRIC	(KERN_DEF_METRIC - 1)
#define COA_ROUTE_METRIC	(KERN_DEF_METRIC)

struct hoa_usable_address {
	struct mblty_network_address *address;
	struct heap_item entry;
};

extern void mipv6_mn_dhaad_init();
extern void mipv6_mn_ro_state_init();

static void mn_hoa_change_coa(struct mipv6_mn_hoa *);

static LIST_DEF(ha_list);
static LIST_DEF(hoa_list);

static mblty_tunnel_factory_t *mn_tun_factory;
static struct mipv6_mn_hoa *default_hoa = NULL;
extern struct mipv6_mn_binding_ops mipv6_mn_ro_binding_ops;

static struct mblty_addr_category hoa_category = {
	.name = "hoa",
};

static const char *_mn_locations[] = {
	"Limbo",
	"At Home",
	"In foreign network",
};

static struct in6_prefix default_route = {
	.address = IN6ADDR_ANY_INIT,
	.prefixlen = 0,
};

static inline int
addr_in_homenet(struct mipv6_mn_hoa *hoa, mblty_network_address_t *addr)
{
	return mblty_same_prefix(&hoa->a, addr);
}

static inline struct in6_addr *
hoa_addr(struct mipv6_mn_hoa *hoa)
{
	return mblty_get_addr(&hoa->a);
}

static inline struct mipv6_mn_ha_router *
hoa_get_ha(struct mipv6_mn_hoa *hoa)
{
	return container_of(mblty_addr_router(&hoa->a),
			    struct mipv6_mn_ha_router, r);
}

static inline struct in6_addr *
hoa_get_ha_addr(struct mipv6_mn_hoa *hoa)
{
	return &hoa_get_ha(hoa)->common->address;
}

static inline struct mipv6_mn_hoa *
hoa_from(struct mblty_network_address *addr)
{
	return container_of(addr, struct mipv6_mn_hoa, a);
}

static inline struct mipv6_mn_hoa *
hoa_from_bctx(struct mipv6_binding_context *ctx)
{
	return container_of(ctx, struct mipv6_mn_hoa, binding_ctx);
}

static inline struct hoa_usable_address *
usable_address(struct heap_item *item)
{
	if (item == NULL)
		return NULL;
	return container_of(item, struct hoa_usable_address, entry);
}

static inline struct mblty_network_address *
hoa_us_head(struct mipv6_mn_hoa *hoa)
{
	if (heap_empty(&hoa->lower_list))
		return NULL;
	else
		return usable_address(heap_top(&hoa->lower_list))->address;
}

static inline int
hoa_is_default(struct mipv6_mn_hoa *hoa)
{
	return default_hoa == hoa;
}

mipv6_mn_ha_t *
mipv6_get_home_agent(struct in6_addr *address)
{
	mipv6_mn_ha_t *ha;

	list_for_each_entry (ha, &ha_list, entry) {
		if (in6_addr_compare(&ha->address, address) == 0)
			return ha;
	}

	return NULL;
}

static mipv6_mn_ha_t *
mipv6_mn_grab_homeagent(mipv6_mn_ha_t *homeagent)
{
	if (homeagent)
		homeagent->refcount++;
	return homeagent;
}

static struct mipv6_mn_ha *
mipv6_mn_get_ha_common(struct in6_addr *address)
{
	struct mipv6_mn_ha *ha = mipv6_get_home_agent(address);

	if (ha == NULL) {
		char buf1[INET6_ADDRSTRLEN];

		ha = allocate_object(struct mipv6_mn_ha);
		if (ha == NULL)
			return NULL;

		in6_addr_copy(&ha->address, address);
		ha->refcount = 0;
		list_init(&ha->instances);
		ha->flags = 0;
		memset(&ha->def_eui64, 0, sizeof(ha->def_eui64));

		list_add_tail(&ha->entry, &ha_list);

		debug_log(0, "Added Home-Agent %s\n", format_addr(buf1, address));
	}

	return mipv6_mn_grab_homeagent(ha);
}

static void
mipv6_mn_put_ha_common(struct mipv6_mn_ha *ha)
{
	debug_assert(ha && ha->refcount > 0,
		     "Consistency problem when releasing HA instance");

	ha->refcount--;

	if (ha->refcount == 0) {
		list_del(&ha->entry);
		free_object(ha);
	}
}

static void
mipv6_mn_remove_ha(mblty_router_t *rt)
{
	struct mipv6_mn_ha_router *ha =
		container_of(rt, struct mipv6_mn_ha_router, r);

	/* Release prefixes and unlink router instance */
	mblty_deinit_router(rt);

	/* Release Home-Agent reference */
	mipv6_mn_put_ha_common(ha->common);
	ha->common = NULL;

	/* Release MN tunnel interface reference */
	mblty_put_interface(ha->tun_intf);
	ha->tun_intf = NULL;
	/* Destroy tunnel interface to HA */
	mblty_tunnel_release(ha->tunnel);
	ha->tunnel = NULL;

	free_object(ha);
}

static mblty_router_ops_t ha_ops = {
	.remove = mipv6_mn_remove_ha,
};

static mipv6_mn_ha_router_t *
mipv6_mn_get_ha(mipv6_mn_ha_t *homeagent, mblty_interface_t *tun_intf,
		mblty_tunnel_t *tunnel)
{
	mipv6_mn_ha_router_t *ha_r;

	list_for_each_entry (ha_r, &homeagent->instances, instance) {
		if (ha_r->tunnel == tunnel)
			return ha_r;
	}

	ha_r = allocate_object(mipv6_mn_ha_router_t);
	if (ha_r == NULL)
		return NULL;

	ha_r->common = mipv6_mn_grab_homeagent(homeagent);
	ha_r->tun_intf = mblty_grab_interface(tun_intf);
	ha_r->tunnel = tunnel;

	list_add_tail(&ha_r->instance, &homeagent->instances);

	mblty_init_router(&ha_r->r, tun_intf, &homeagent->address, &ha_ops, 1);

	return ha_r;
}

int
mipv6_is_ha_router(struct mblty_router *rt)
{
	struct mipv6_mn_ha_router *ha_r;
	struct mipv6_mn_ha *ha;

	list_for_each_entry (ha, &ha_list, entry) {
		list_for_each_entry (ha_r, &ha->instances, instance) {
			if (&ha_r->r == rt)
				return 1;
		}
	}

	return 0;
}

static int
mn_hoa_compare_address(struct heap *h, struct heap_item *e1,
		       struct heap_item *e2)
{
	mipv6_mn_hoa_t *hoa = container_of(h, struct mipv6_mn_hoa, lower_list);
	struct hoa_usable_address *a1, *a2;

	a1 = usable_address(e1);
	a2 = usable_address(e2);

	return hoa->compare_coa_pol(hoa, a1->address, a2->address);
}

static void
mn_hoa_update_location_with(mipv6_mn_hoa_t *hoa, mipv6_location_t newlocation,
			    mblty_network_address_t *new_coa)
{
	mipv6_mn_ha_router_t *ha = hoa_get_ha(hoa);
	mipv6_location_t oldloc = hoa->location;
	struct mblty_tunnel *tun = ha->tunnel;
	mblty_policy_t oldpol;

	if (hoa->location != newlocation) {
		debug_log(1, "MN location changed %s -> %s\n",
			  _mn_locations[hoa->location],
			  _mn_locations[newlocation]);

		/* new location handling */
		if (newlocation == MIPV6_MN_LOC_FOREIGN) {
			mblty_os_intf_set_up(tun->osh, 1);
			mblty_os_intf_disable(tun->osh,
					      MBLTY_OS_INTF_CAP_AUTOCONF);
		}

		/* old location handling */
		if (hoa->location == MIPV6_MN_LOC_FOREIGN)
			mblty_os_intf_set_up(tun->osh, 0);

		hoa->location = newlocation;
	}

	if (new_coa == hoa->active_coa)
		return;

	if (hoa->location == MIPV6_MN_LOC_FOREIGN) {
		if (mblty_tunnel_update(tun, mblty_get_addr(new_coa),
					hoa_get_ha_addr(hoa)) < 0) {
			debug_log(1, "Failed to update tunnel endpoints.\n");
		}
	}

	if (oldloc == MIPV6_MN_LOC_HOME) {
		if (hoa->flags & MIPV6_MN_HOA_PROTECTED) {
			ndisc_addr_unregister(&hoa->nar);
			hoa->flags &= ~MIPV6_MN_HOA_PROTECTED;
		}
	}

	if (hoa->location == MIPV6_MN_LOC_HOME) {
		if (ndisc_addr_register(&hoa->nar, mblty_addr_intf(new_coa),
					mblty_addr_parent(&hoa->a), NULL) == 0) {
			hoa->flags |= MIPV6_MN_HOA_PROTECTED;
			hoa->nar.flags = NDISC_ADDRREC_F_NOISY;
			ndisc_addr_proceed(&hoa->nar);
		}
	}

	if (hoa->active_coa)
		mblty_copy_policy(&oldpol, &hoa->defroute);

	/* apply new policy before deleting previous one */
	if (new_coa) {
		mblty_policy_t *pol = &hoa->defroute;

		pol->destination = &default_route;

		if (hoa_is_default(hoa))
			pol->source = NULL;
		else
			pol->source = hoa_addr(hoa);

		if (addr_in_homenet(hoa, new_coa)) {
			pol->flags = 0;
			pol->intf = mblty_addr_intf(new_coa)->osh;
			pol->gateway =
				mblty_rtr_address(mblty_addr_router(new_coa));
		} else {
			pol->flags = MBLTY_POLICY_F_NOTIFY;
			pol->intf = hoa_get_ha(hoa)->tunnel->osh;
			pol->gateway = NULL;
		}

		mblty_add_policy(pol);
	}

	if (hoa->active_coa)
		mblty_delete_policy(&oldpol);

	hoa->active_coa = new_coa;
}

static void
mn_hoa_update_location(mipv6_mn_hoa_t *hoa, mipv6_location_t newlocation)
{
	mn_hoa_update_location_with(hoa, newlocation, hoa_us_head(hoa));
}

static void
mn_hoa_bctx_completed_reg(struct mipv6_binding_context *ctx)
{
	struct mipv6_mn_hoa *hoa = ctx->owner;
	char buf1[INET6_ADDRSTRLEN];
	int location;

	debug_log(2, "HoA %s completed registration with Home Agent.\n",
		  format_addr(buf1, hoa_addr(hoa)));

	/* the binding context will only be acked when
	 * the registration completes for the top coa */

	if (addr_in_homenet(hoa, hoa_us_head(hoa)))
		location = MIPV6_MN_LOC_HOME;
	else
		location = MIPV6_MN_LOC_FOREIGN;

	mn_hoa_update_location(hoa, location);

	hoa->ops->post_update(hoa);
}

static void
hoa_defroute_added(mblty_policy_t *pol, int result)
{
	char buf1[INET6_ADDRSTRLEN];
	struct mipv6_mn_hoa *hoa =
		container_of(pol, struct mipv6_mn_hoa, defroute);

	debug_log(7, "HoA %s, added default route = %i.\n",
		  format_addr(buf1, hoa_addr(hoa)), result);
}

static void
mn_hoa_lost_active_coa(mipv6_mn_hoa_t *hoa)
{
	mn_hoa_update_location_with(hoa, MIPV6_MN_LOC_LIMBO, NULL);
	mipv6_reset_binding(&hoa->binding_ctx);
}

static void
mn_hoa_in_loopback(struct mipv6_mn_hoa *hoa, int on)
{
	if (on)
		mblty_intf_addr_change_to(&hoa->inst,
					  MBLTY_INTF_ADDR_STATE_READY);
	else
		mblty_intf_addr_change_to(&hoa->inst,
					  MBLTY_INTF_ADDR_STATE_NOINFO);
}

static void
mipv6_mn_removing_hoa(mblty_network_address_t *addr)
{
	struct mipv6_mn_hoa *hoa = hoa_from(addr);
	char buf1[INET6_ADDRSTRLEN];

	debug_log(1, "Removing HoA %s\n", format_addr(buf1,
		  mblty_get_addr(addr)));

	hoa->ops->clear_state(hoa);
	mipv6_mn_hoa_set_ipsec_auth(hoa, 0);
	mipv6_mn_hoa_set_nai(hoa, NULL);

	mn_hoa_lost_active_coa(hoa);

	mipv6_remove_binding_context(&hoa->binding_ctx);

	while (!heap_empty(&hoa->lower_list)) {
		free_object(usable_address(heap_top_and_pop(&hoa->lower_list)));
	}

	heap_free(&hoa->lower_list);

	list_del(&hoa->entry);

	mn_hoa_in_loopback(hoa, 0);
	mblty_intf_addr_remove(&hoa->inst);
}

static int
mipv6_mn_hoa_default_compare_coa_pol(struct mipv6_mn_hoa *hoa,
				     struct mblty_network_address *a1,
				     struct mblty_network_address *a2)
{
	int pref1, pref2;

	/* always push CoAs which are in home network forward */
	if (addr_in_homenet(hoa, a1) && !addr_in_homenet(hoa, a2))
		return -1;

	pref1 = mblty_addr_intf(a1)->preference;
	pref2 = mblty_addr_intf(a2)->preference;

	pref1 += mblty_addr_preference(a1);
	pref2 += mblty_addr_preference(a2);

	if (pref1 != pref2)
		return pref2 - pref1;

	return 1;
}

static mblty_network_address_ops_t hoa_ops = {
	.removing = mipv6_mn_removing_hoa,
};

static mblty_policy_ops_t hoa_defroute_pol_ops = {
	.added = hoa_defroute_added,
};

struct mipv6_mn_hoa *
mipv6_mn_alloc_hoa(struct mblty_router_prefix *pfx, struct in6_addr *addr)
{
	char buf1[INET6_ADDRSTRLEN];
	mblty_os_intf_t *loopback;
	mipv6_mn_hoa_t *hoa;

	hoa = allocate_object(struct mipv6_mn_hoa);
	if (hoa == NULL)
		return NULL;

	if (mblty_init_address(&hoa->a, addr, &hoa_category, pfx,
			       &hoa_ops) < 0) {
		free_object(hoa);
		return NULL;
	}

	mipv6_init_binding_context(&hoa->binding_ctx, &hoa->a,
				   mblty_rtr_address(pfx->owner));

	hoa->binding_ctx.owner = hoa;
	hoa->binding_ctx.flags |= MIPV6_BCTX_WANT_ACK | MIPV6_BCTX_HOMEREG |
				  MIPV6_BCTX_USE_ALT_COA;
	hoa->binding_ctx.cb_completed_reg = mn_hoa_bctx_completed_reg;

	hoa->location = MIPV6_MN_LOC_LIMBO;
	hoa->flags = 0;
	heap_init(&hoa->lower_list);
	hoa->lower_list.compare = mn_hoa_compare_address;
	list_init(&hoa->individual_ctxs);
	hoa->active_coa = NULL;

	mblty_init_policy(&hoa->defroute);
	hoa->defroute.ops = &hoa_defroute_pol_ops;

	hoa->ops = &mipv6_mn_ro_binding_ops;
	hoa->compare_coa_pol = mipv6_mn_hoa_default_compare_coa_pol;

	list_add_tail(&hoa->entry, &hoa_list);

	loopback = mblty_os_intf_get_loopback();
	debug_assert(loopback, "No loopback interface available?");

	mblty_intf_addr_init(&hoa->inst, loopback, hoa_addr(hoa));
	hoa->inst.flags = MBLTY_INTF_ADDR_F_HOME_ADDRESS |
			  MBLTY_INTF_ADDR_F_MANAGED;

	mn_hoa_in_loopback(hoa, 1);

	if (default_hoa == NULL)
		default_hoa = hoa;

	debug_log(0, "Added HoA %s\n", format_addr(buf1, addr));

	return hoa;
}

struct mipv6_mn_hoa *
mipv6_mn_get_hoa(struct in6_addr *addr)
{
	struct mipv6_mn_hoa *hoa;

	list_for_each_entry (hoa, &hoa_list, entry) {
		if (in6_addr_compare(hoa_addr(hoa), addr) == 0)
			return hoa;
	}

	return NULL;
}

static struct mblty_router_prefix *
mipv6_mn_announced_home_pfx(struct mipv6_mn_ha_router *ha,
			    struct in6_prefix *pfx)
{
	return mblty_router_announced_prefix(&ha->r, pfx,
					     MBLTY_NETPFX_NO_DAD |
					     MBLTY_NETPFX_NO_AUTOCONF);
}

static mipv6_mn_ha_router_t *
mipv6_mn_instantiate_ha(mipv6_mn_ha_t *homeagent, struct in6_addr *hoa)
{
	mblty_interface_t *tun_intf;
	mipv6_mn_ha_router_t *ha_r;
	mblty_tunnel_t *tun;

	tun = mblty_tunnel_alloc(mn_tun_factory, &homeagent->address, hoa);
	if (tun == NULL)
		return NULL;

	tun_intf = mblty_create_interface(tun->osh, 0, 1);
	if (tun_intf == NULL) {
		mblty_tunnel_release(tun);
		return NULL;
	}

	if (homeagent->flags & MIPV6_MN_HA_HAS_DEF_EUI64)
		mblty_interface_set_eui64(tun_intf, &homeagent->def_eui64);

	ha_r = mipv6_mn_get_ha(homeagent, tun_intf, tun);
	if (ha_r == NULL) {
		mblty_put_interface(tun_intf);
		mblty_tunnel_release(tun);
	}

	return ha_r;
}

void
mipv6_mn_allocate_hoa(struct in6_addr *ha, struct in6_prefix *pfx,
		      struct in6_addr *hoa, int fact)
{
	mblty_router_prefix_t *homepfx;
	mipv6_mn_ha_router_t *ha_r;
	mipv6_mn_ha_t *homeagent;
	struct in6_prefix tmp;

	/* Phase 1: obtain the Home Agent instance */
	homeagent = mipv6_mn_get_ha_common(ha);
	if (homeagent == NULL)
		return;

	/* Phase 2: instantiate a new Home Agent Router for usage
	 *          with the specific Home prefix and Home address */
	ha_r = mipv6_mn_instantiate_ha(homeagent, hoa);
	mipv6_mn_put_ha_common(homeagent);

	if (ha_r == NULL)
		return;

	/* Phase 3: attached the specified Home prefix to the
	 *          instantiated Home Agent Router */
	in6_prefix_copy_applied(&tmp, pfx);
	homepfx = mipv6_mn_announced_home_pfx(ha_r, &tmp);
	if (homepfx == NULL) {
		mblty_remove_router(&ha_r->r);
		return;
	}

	/* Phase 4: instantiate the specified Home Address */
	mipv6_mn_alloc_hoa(homepfx, hoa);
}

void
mipv6_mn_foreach_hoa(int (*cb)(struct mipv6_mn_hoa *, void *), void *arg)
{
	struct mipv6_mn_hoa *hoa, *tmp;

	list_for_each_entry_safe (hoa, tmp, &hoa_list, entry) {
		if (cb(hoa, arg) < 0)
			return;
	}
}

static void
mn_hoa_finish_update(mipv6_mn_hoa_t *hoa, mblty_network_address_t *coa)
{
	if (coa == NULL)
		return;

	if (!mipv6_auth_data_is_valid(&hoa->binding_ctx))
		return;

	if (addr_in_homenet(hoa, coa))
		coa = NULL;

	hoa->ops->pre_update(hoa, coa);

	mipv6_update_binding(&hoa->binding_ctx, mblty_addr_parent(coa));
}

static void
mn_hoa_update_binding(struct mipv6_mn_hoa *hoa)
{
	struct mipv6_auth_data *auth_data = hoa->binding_ctx.auth;
	mblty_network_address_t *coa = hoa_us_head(hoa);

	if (auth_data && auth_data->ops->update)
		auth_data->ops->update(&hoa->binding_ctx,
				       mblty_addr_parent(coa));
	else
		mn_hoa_finish_update(hoa, coa);
}

static void
hoa_ipsec_is_valid(struct mipv6_auth_data *auth_data)
{
	mipv6_mn_hoa_t *hoa = hoa_from_bctx(auth_data->parent);

	mn_hoa_finish_update(hoa, hoa_us_head(hoa));
}

void
mipv6_mn_hoa_set_ipsec_auth(struct mipv6_mn_hoa *hoa, int val)
{
	mipv6_binding_context_t *ctx = &hoa->binding_ctx;

	if (val && ctx->auth == NULL) {
		ctx->auth = mipv6_alloc_ipsec_auth_data(ctx);
		ctx->auth->updated = hoa_ipsec_is_valid;
	} else if (!val && ctx->auth) {
		mipv6_auth_data_release(ctx->auth);
		ctx->auth = NULL;
	}
}

int
mipv6_mn_hoa_set_nai(struct mipv6_mn_hoa *hoa, const char *nai)
{
	char buf1[INET6_ADDRSTRLEN];

	if (hoa->binding_ctx.nai == NULL && nai == NULL)
		return 0;

	if (hoa->binding_ctx.nai) {
		free(hoa->binding_ctx.nai);
		hoa->binding_ctx.nai = NULL;
		hoa->binding_ctx.flags &= ~MIPV6_BCTX_HAS_NAI;
	}

	if (nai) {
		hoa->binding_ctx.nai = strdup(nai);
		if (hoa->binding_ctx.nai)
			hoa->binding_ctx.flags |= MIPV6_BCTX_HAS_NAI;
	}

	debug_log(3, "HoA %s NAI is now %s.\n",
		  format_addr(buf1, hoa_addr(hoa)), nai);

	return hoa->binding_ctx.nai != NULL;
}

static void
mn_hoa_lost_connectivity(mipv6_mn_hoa_t *hoa)
{
	mn_hoa_lost_active_coa(hoa);
	mipv6_clear_binding(&hoa->binding_ctx);
}

static void
mn_hoa_completed_ha_ns(ndisc_handler_context_t *ctx, int result, void *arg)
{
	struct mipv6_mn_hoa *hoa = arg;
	struct mblty_interface *intf;
	uint8_t *lladdr = NULL;
	int addrlen = 0;

	debug_log(4, "mn_hoa_completed_ha_ns(%i bytes, %i, %p)\n",
		  ctx->length, result, arg);

	if (result != MBLTY_NEIGH_SOLICIT_OK) {
		/* If the Home agent did not reply, we assume it
		 * died or the previous binding for some reason is
		 * no longer active. */
		mn_hoa_lost_connectivity(hoa);
		if (hoa_us_head(hoa))
			mn_hoa_change_coa(hoa);
		return;
	}

	while (ndisc_handctx_next_opt(ctx)) {
		if (ctx->opt.hdr == NULL)
			return;

		if (ctx->opt.hdr->nd_opt_type == ND_OPT_TARGET_LINKADDR) {
			if (lladdr)
				return;
			lladdr = ctx->opt.raw + 2;
			addrlen = ctx->opt.hdr->nd_opt_len * 8 - 2;
		}
	}

	if (lladdr == NULL) {
		/* no lladdr.. */
		return;
	}

	intf = mblty_addr_intf(hoa_us_head(hoa));

	/* add or update HA's entry in the neighbor cache, so the
	 * BU sent by mipv6_update_binding below doesn't require
	 * neighbor discovery */
	if (mblty_os_intf_neigh_update(intf->osh, hoa_get_ha_addr(hoa),
				       lladdr, addrlen) < 0) {
		/* failed to update neigh cache.. */
		return;
	}

	/* trigger BU to HA to release the binding */
	mn_hoa_update_binding(hoa);
}

static void
mn_hoa_prepare_return_home(struct mipv6_mn_hoa *hoa)
{
	struct mblty_network_address *head = hoa_us_head(hoa);
	struct mblty_interface *intf = mblty_addr_intf(head);

	/* when returning home, we must resolve the
	 * HA's address via neighbor discovery, but
	 * we can't use our home address as source, as
	 * the HA is claiming it */

	/* XXX check if we already have the HA in the
	 * neighbor cache */

	ndisc_do_neigh_solicit(intf->osh, hoa_addr(hoa),
			       mn_hoa_completed_ha_ns, hoa);
}

static void
mn_hoa_change_coa(struct mipv6_mn_hoa *hoa)
{
	struct mblty_network_address *head = hoa_us_head(hoa);
	char buf1[INET6_ADDRSTRLEN], buf2[INET6_ADDRSTRLEN];

	if (head == NULL) {
		debug_log(1, "HoA %s lost connectivity.\n",
			  format_addr(buf1, hoa_addr(hoa)));

		mn_hoa_lost_connectivity(hoa);
		return;
	}

	if (addr_in_homenet(hoa, head)) {
		if (hoa->location == MIPV6_MN_LOC_FOREIGN) {
			debug_log(1, "*HANDOVER* HoA %s returning home.\n",
				  format_addr(buf1, hoa_addr(hoa)));

			mn_hoa_prepare_return_home(hoa);
		} else {
			mn_hoa_update_location(hoa, MIPV6_MN_LOC_HOME);
		}
	} else {
		debug_log(1, "%sHoA %s changed CoA to %s.\n",
			  hoa->location != MIPV6_MN_LOC_LIMBO ?
			  "*HANDOVER* " : "", format_addr(buf1, hoa_addr(hoa)),
			  format_addr(buf2, mblty_get_addr(head)));

		/* adding new best coa */
		mn_hoa_update_binding(hoa);
	}
}

mblty_network_address_t *
mipv6_mn_hoa_top_coa(struct mipv6_mn_hoa *hoa)
{
	return hoa_us_head(hoa);
}

static int
usable_address_find_addr(struct heap_item *item, void *arg)
{
	mblty_network_address_t *addr = arg;

	if (usable_address(item)->address == addr)
		return 0;

	return -1;
}

static struct hoa_usable_address *
hoa_get_top_coa(struct mipv6_mn_hoa *hoa, mblty_network_address_t *addr)
{
	return usable_address(heap_first_match(&hoa->lower_list,
					       usable_address_find_addr,
					       addr));
}

static int
mn_hoa_distribute_address(struct mipv6_mn_hoa *hoa, void *addrptr)
{
	mblty_network_address_t *addr = addrptr;
	struct hoa_usable_address *new_address;

	/* avoid duplicates */
	if (hoa_get_top_coa(hoa, addr))
		return 0;

	new_address = allocate_object(struct hoa_usable_address);
	if (new_address == NULL) {
		char buf1[INET6_ADDRSTRLEN];
		debug_log(1, "Failed to allocate address instance for %s.\n",
			  format_addr(buf1, mblty_get_addr(addr)));
		return 0;
	}

	new_address->address = addr;

	heap_push(&hoa->lower_list, &new_address->entry);

	if (hoa_us_head(hoa) == addr) {
		/* if the new CoA is the preferred, use it */
		mn_hoa_change_coa(hoa);
	}

	return 0;
}

static int
mn_hoa_lost_address(struct mipv6_mn_hoa *hoa, void *addrptr)
{
	struct mblty_network_address *address = addrptr;
	struct mblty_network_address *prevhead;
	struct hoa_usable_address *node;

	node = hoa_get_top_coa(hoa, address);
	if (node == NULL)
		return 0;

	prevhead = hoa_us_head(hoa);

	heap_remove(&hoa->lower_list, &node->entry);
	free_object(node);

	if (hoa->active_coa == address) {
		/* lost the active CoA, connectivity will be lost */
		mn_hoa_lost_active_coa(hoa);
		/* try to force a new update if addresses are available */
		mn_hoa_change_coa(hoa);
	} else if (prevhead == address) {
		/* lost the address we were probably binding to,
		 * force a new update */
		mn_hoa_change_coa(hoa);
	}

	hoa->ops->invalidate_addr(hoa, address);

	return 0;
}

void
mipv6_mn_distribute_address(struct mblty_network_address *addr)
{
	mipv6_mn_foreach_hoa(mn_hoa_distribute_address, addr);
}

void
mipv6_mn_lost_address(struct mblty_network_address *addr)
{
	mipv6_mn_foreach_hoa(mn_hoa_lost_address, addr);
}

static void
mn_state_shutdown()
{
	mblty_return_tunnel_factory(mn_tun_factory);
	mn_tun_factory = NULL;
}

static struct mblty_shutdown_entry mn_shutdown = {
	.handler = mn_state_shutdown,
};

void
mipv6_mn_state_init()
{
	mn_tun_factory = mblty_obtain_tunnel_factory(MBLTY_TUN_TYPE_IP6IP6);
	if (mn_tun_factory == NULL)
		perform_shutdown("IPv6-over-IPv6 tunnels not available.");

	mblty_register_shutdown(&mn_shutdown);

	mblty_register_addr_category(&hoa_category);

	mipv6_mn_dhaad_init();
	mipv6_mn_ro_state_init();
}

