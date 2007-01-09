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
#include <netinet/in.h>

#include <mblty/events.h>
#include <mblty/router.h>
#include <mblty/interface.h>
#include <mblty/base-support.h>

static LIST_DEF(routers);

static void nud_router_reachable(void *, int linkup);
static void nud_router_unreachable(void *);
static void nud_router_flags_changed(void *, uint32_t);
static void nud_router_perm_unreachable(void *);

static mblty_reachability_ops_t rtr_reach_ops = {
	.reachable = nud_router_reachable,
	.unreachable = nud_router_unreachable,
	.flags_changed = nud_router_flags_changed,
	.permanently_unreachable = nud_router_perm_unreachable,
};

void
mblty_router_flags_changed(mblty_router_t *rtr, uint32_t oldflags)
{
	if (rtr->ops && rtr->ops->flags_changed)
		rtr->ops->flags_changed(rtr, oldflags);
}

static void
change_router_flags(mblty_router_t *rtr, uint32_t newflags)
{
	uint32_t oldflags = rtr->flags;

	if (newflags == oldflags)
		return;

	rtr->flags = newflags;

	mblty_router_flags_changed(rtr, oldflags);
}

static void
router_no_longer_default(suptimer_t *tmr, void *arg)
{
	char buf1[INET6_ADDRSTRLEN];
	mblty_router_t *rtr = arg;

	rtr->flags &= ~MBLTY_ROUTER_RUNNING_DEFAULT;

	debug_log(0, "Router %s default timer expired.\n",
		  format_addr(buf1, mblty_rtr_address(rtr)));

	mblty_remove_router(rtr);
}

mblty_router_t *
mblty_init_router(mblty_router_t *rt, struct mblty_interface *intf,
		  struct in6_addr *addr, mblty_router_ops_t *ops, int link)
{
	rt->name.intf = intf;
	in6_addr_copy(&rt->name.address, addr);
	rt->name.flags = 0;
	rt->name.instance = rt;

	rt->link_addr = NULL;
	rt->flags = 0;
	rt->use_count = 0;
	timer_init_with(&rt->default_timer, "default router timeout",
			router_no_longer_default, rt);
	list_init(&rt->prefixes);
	rt->ops = ops;
	rt->reach = NULL;

	list_init(&rt->names);

	if (link) {
		list_add_tail(&rt->rtrs, &routers);

		if (intf)
			mblty_link_router(intf, rt);
	}

	return rt;
}

void
mblty_link_router(struct mblty_interface *intf, mblty_router_t *rt)
{
	char buf1[INET6_ADDRSTRLEN];

	debug_assert(intf && rt, "Missing interface or router when linking");

	list_add_tail(&rt->entry, &intf->routers);
	list_add_tail(&rt->name.entry, &intf->router_names);
	rt->name.intf = intf;

	rt->flags |= MBLTY_ROUTER_IS_LINKED;

	debug_log(1, "Linked router %s to %s\n",
		  format_addr(buf1, mblty_rtr_address(rt)), intf->osh->name);

	mblty_linked_router(rt);
}

mblty_router_name_t *
mblty_add_router_alias(mblty_router_t *rtr, struct in6_addr *addr)
{
	char buf1[INET6_ADDRSTRLEN], buf2[INET6_ADDRSTRLEN];
	mblty_interface_t *intf = mblty_rtr_intf(rtr);
	mblty_router_name_t *name;

	name = allocate_object(mblty_router_name_t);
	if (name == NULL)
		return NULL;

	debug_log(6, "Adding router alias %s to %s.\n", format_addr(buf1,
		  addr), format_addr(buf2, &rtr->name.address));

	name->intf = intf;
	in6_addr_copy(&name->address, addr);
	name->flags = MBLTY_RTRNAME_ALIAS;
	name->instance = rtr;

	list_add_tail(&name->entry, &intf->router_names);
	list_add_tail(&name->name_entry, &rtr->names);

	return name;
}

void
mblty_unlink_router(mblty_router_t *rt)
{
	struct mblty_interface *intf = mblty_rtr_intf(rt);
	mblty_router_name_t *name, *tmp;

	debug_assert(rt && intf, "Missing intf or router when unlinking");

	if (rt->flags & MBLTY_ROUTER_IS_LINKED) {
		char buf1[INET6_ADDRSTRLEN];

		list_del(&rt->entry);
		list_del(&rt->name.entry);
		rt->name.intf = NULL;

		list_del(&rt->rtrs);

		debug_log(1, "Unlinked router %s from %s\n",
			  format_addr(buf1, mblty_rtr_address(rt)),
			  intf->osh->name);
	}

	list_for_each_entry_safe (name, tmp, &rt->names, name_entry) {
		list_del(&name->entry);
		free_object(name);
	}

	if (rt->reach) {
		mblty_release_reach(rt->reach);
		rt->reach = NULL;
	}
}

void
mblty_using_router(mblty_router_t *rtr, int inc)
{
	debug_log(7, "mblty_using_router(%p, %i)\n", rtr, inc);

	rtr->use_count += inc;

	debug_assert(rtr->use_count >= 0, "Invalid router use count.\n");
}

void
mblty_router_remove_prefix(mblty_router_prefix_t *netpfx)
{
	char buf1[INET6_ADDRSTRLEN], buf2[INET6_PREFIXSTRLEN];

	if (IN6_IS_ADDR_UNSPECIFIED(mblty_rtr_address(netpfx->owner))) {
		debug_log(0, "Removing prefix %s.\n",
			  format_prefix(buf2, mblty_get_rtr_pfx(netpfx)));
	} else {
		debug_log(0, "Router %s, removing prefix %s.\n",
			  format_addr(buf1, mblty_rtr_address(netpfx->owner)),
			  format_prefix(buf2, mblty_get_rtr_pfx(netpfx)));
	}

	mblty_clear_prefix_addresses(netpfx, NULL);

	mblty_intf_put_prefix(mblty_rtr_intf(netpfx->owner), netpfx);

	if (netpfx->flags & MBLTY_NETPFX_TEMPORARY)
		timer_remove(&netpfx->timer);

	list_del(&netpfx->entry);
	free_object(netpfx);
}

void
mblty_deinit_router(mblty_router_t *rtr)
{
	mblty_router_prefix_t *pfx;

	if (rtr->flags & MBLTY_ROUTER_RUNNING_DEFAULT)
		timer_remove(&rtr->default_timer);

	while (list_get_head(pfx, &rtr->prefixes, entry)) {
		mblty_router_remove_prefix(pfx);
	}

	mblty_unlink_router(rtr);

	debug_assert(rtr->use_count == 0,
		     "Not all router users released their references.\n");

	if (rtr->link_addr) {
		mblty_release_link_addr(rtr->link_addr);
		rtr->link_addr = NULL;
	}
}

void
mblty_update_router_lifetime(mblty_router_t *rtr, int lifetime)
{
	uint32_t flags = rtr->flags;

	if (lifetime) {
		if (flags & MBLTY_ROUTER_RUNNING_DEFAULT) {
			timer_update(&rtr->default_timer, lifetime);
		} else {
			flags |= MBLTY_ROUTER_RUNNING_DEFAULT;
			timer_add(&rtr->default_timer, lifetime);
		}
	} else if (rtr->flags & MBLTY_ROUTER_RUNNING_DEFAULT) {
		flags &= ~MBLTY_ROUTER_RUNNING_DEFAULT;
		timer_remove(&rtr->default_timer);
	}

	change_router_flags(rtr, flags);
}

mblty_router_prefix_t *
mblty_router_get_prefix(mblty_router_t *rtr, struct in6_prefix *pfx)
{
	mblty_router_prefix_t *rtpfx;

	list_for_each_entry (rtpfx, &rtr->prefixes, entry) {
		if (in6_prefix_compare(mblty_get_rtr_pfx(rtpfx), pfx) == 0) {
			return rtpfx;
		}
	}

	return NULL;
}

static void
prefix_timed_out(suptimer_t *tmr, void *arg)
{
	mblty_router_remove_prefix((mblty_router_prefix_t *)arg);
}

static mblty_router_prefix_t *
mblty_alloc_router_prefix(mblty_router_t *rt, struct in6_prefix *prefix)
{
	mblty_interface_t *intf = mblty_rtr_intf(rt);
	mblty_router_prefix_t *rtrpfx;

	rtrpfx = allocate_object(mblty_router_prefix_t);
	if (rtrpfx == NULL)
		return NULL;

	if (mblty_intf_get_prefix(intf, prefix, rtrpfx) == NULL) {
		free_object(rtrpfx);
		return NULL;
	}

	rtrpfx->owner = rt;
	rtrpfx->flags = 0;

	list_init(&rtrpfx->addresses);

	return rtrpfx;
}

mblty_router_prefix_t *
mblty_router_announced_prefix(mblty_router_t *rtr, struct in6_prefix *prefix,
			      uint32_t flags)
{
	char buf1[INET6_ADDRSTRLEN], buf2[INET6_PREFIXSTRLEN];
	mblty_router_prefix_t *pfx;

	pfx = mblty_alloc_router_prefix(rtr, prefix);
	debug_assert(pfx, "Failed to allocate network prefix");

	pfx->flags = flags;
	list_add_tail(&pfx->entry, &rtr->prefixes);

	timer_init_with(&pfx->timer, "prefix preferred timer",
			prefix_timed_out, pfx);

	pfx->address_available = NULL;

	if (IN6_IS_ADDR_UNSPECIFIED(mblty_rtr_address(rtr))) {
		debug_log(0, "Added prefix %s.\n", format_prefix(buf2, prefix));
	} else {
		debug_log(0, "Router %s, added prefix %s.\n",
			  format_addr(buf1, mblty_rtr_address(rtr)),
			  format_prefix(buf2, prefix));
	}

	mblty_interface_added_network_prefix(pfx);

	return pfx;
}

void
mblty_prefix_update_lifetimes(mblty_router_prefix_t *pfx, uint32_t valid,
			      uint32_t preferred)
{
	/* XXX handle preferred lifetime */

	if (valid == 0) {
		mblty_router_remove_prefix(pfx);
	} else if (valid == 0xffffffff) {
		if (pfx->flags & MBLTY_NETPFX_TEMPORARY)
			timer_remove(&pfx->timer);
		pfx->flags &= ~MBLTY_NETPFX_TEMPORARY;
	} else {
		if (pfx->flags & MBLTY_NETPFX_TEMPORARY)
			timer_update(&pfx->timer, valid * 1000);
		else
			timer_add(&pfx->timer, valid * 1000);

		pfx->flags |= MBLTY_NETPFX_TEMPORARY;
	}
}

static void
router_link_addr_changed(mblty_router_t *rtr)
{
	if (rtr->use_count > 0) {
		debug_log(1, "Router advertised link-addr changed while"
			     " it is being used.\n");
	}
}

void
mblty_router_set_link_addr(mblty_router_t *rtr, uint8_t *addr, int len)
{
	int had = 0;

	if (rtr->link_addr) {
		if (addr) {
			if (mblty_compare_link_addr(rtr->link_addr,
						    addr, len) == 0) {
				/* address isn't changing */
				return;
			} else if (rtr->link_addr->length == len) {
				memcpy(rtr->link_addr->addr, addr, len);
				router_link_addr_changed(rtr);
				return;
			}
		}

		mblty_release_link_addr(rtr->link_addr);
		rtr->link_addr = NULL;

		had = 1;
	}

	if (addr) {
		rtr->link_addr = mblty_alloc_link_addr(addr, len);
		if (had)
			router_link_addr_changed(rtr);
	}
}

void
mblty_foreach_router(void (*cb)(mblty_router_t *, void *), void *arg)
{
	mblty_router_t *rtr;

	list_for_each_entry (rtr, &routers, rtrs) {
		cb(rtr, arg);
	}
}

static void
nud_router_reachable(void *param, int linkup)
{
	mblty_network_address_t *addr, *addrtmp;
	mblty_router_prefix_t *pfx, *pfxtmp;
	mblty_router_t *rtr = param;

	list_for_each_entry_safe (pfx, pfxtmp, &rtr->prefixes, entry) {
		list_for_each_entry_safe (addr, addrtmp, &pfx->addresses,
					  entry) {
			if (addr->ops && addr->ops->reachable)
				addr->ops->reachable(addr);
		}
	}
}

static void
nud_router_unreachable(void *param)
{
	mblty_network_address_t *addr, *addrtmp;
	mblty_router_prefix_t *pfx, *pfxtmp;
	mblty_router_t *rtr = param;

	list_for_each_entry_safe (pfx, pfxtmp, &rtr->prefixes, entry) {
		list_for_each_entry_safe (addr, addrtmp, &pfx->addresses,
					  entry) {
			if (addr->ops && addr->ops->reachable)
				addr->ops->unreachable(addr);
		}
	}
}

static void
nud_router_flags_changed(void *param, uint32_t oldflags)
{
	mblty_router_t *rtr = param;

	if (rtr->reach->flags & MBLTY_REACH_IS_ROUTER)
		return;

	/* stoped being a router */
	mblty_remove_router(rtr);
}

static void
nud_router_perm_unreachable(void *arg)
{
	mblty_remove_router((mblty_router_t *)arg);
}

void
mblty_setup_router_reachability(mblty_router_t *rtr)
{
	rtr->reach->instance = rtr;
	rtr->reach->ops = &rtr_reach_ops;
}

int
mblty_is_router_reachable(mblty_router_t *rtr)
{
	if (rtr->reach == NULL)
		return 0;

	return rtr->reach->baseops->is_reachable(rtr->reach);
}

