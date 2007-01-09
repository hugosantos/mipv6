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

#include "linux-def.h"

void
mblty_intf_addr_init(mblty_intf_addr_t *addr, mblty_os_intf_t *intf,
		     struct in6_addr *address)
{
	addr->intf = intf;
	addr->address = address;
	addr->flags = 0;
	addr->state = addr->newstate =
		addr->pending =	MBLTY_INTF_ADDR_STATE_NOINFO;
	addr->ops = NULL;
}

static void
linux_check_address_consistency(mblty_intf_addr_t *addr)
{
	mblty_intf_addr_state_t oldstate = addr->state;

	addr->state = addr->newstate;

	if (addr->pending != addr->state) {
		mblty_intf_addr_change_to(addr, addr->pending);
	} else {
		if (oldstate == MBLTY_INTF_ADDR_STATE_NOINFO)
			list_add_tail(&addr->entry,
				      &INTF(addr->intf)->addresses);
		else if (addr->state == MBLTY_INTF_ADDR_STATE_NOINFO)
			list_del(&addr->entry);

		if (addr->ops)
			addr->ops->changed_state(addr, oldstate);
	}
}

static void
linux_addr_removed(int result, void *param)
{
	linux_check_address_consistency((mblty_intf_addr_t *)param);
}

static void
linux_addr_added(int result, void *param)
{
	linux_check_address_consistency((mblty_intf_addr_t *)param);
}

void
mblty_intf_addr_change_to(mblty_intf_addr_t *addr,
			  mblty_intf_addr_state_t newstate)
{
	if (addr->state != addr->newstate) {
		/* if we are in the middle of an update, we store
		 * the desired new state and wait for the previous
		 * request to finish as to keep a consistent state */
		if (addr->newstate != newstate)
			addr->pending = newstate;
		return;
	}

	if (addr->state == newstate)
		return;

	if (newstate == MBLTY_INTF_ADDR_STATE_NOINFO) {
		linux_intf_address_remove(addr->intf, addr->address,
					  linux_addr_removed, addr);
	} else {
		uint32_t flags = KERN_ADDR_F_PERMANENT;

		if (addr->flags & MBLTY_INTF_ADDR_F_HOME_ADDRESS)
			flags |= KERN_ADDR_F_HOME_ADDRESS;

		if (addr->flags & MBLTY_INTF_ADDR_F_MANAGED)
			flags |= KERN_ADDR_F_MANAGED;

		if (newstate == MBLTY_INTF_ADDR_STATE_TENTATIVE)
			flags |= KERN_ADDR_F_TENTATIVE;
		else if (newstate == MBLTY_INTF_ADDR_STATE_DEPRECATED)
			flags |= KERN_ADDR_F_DEPRECATED;

		if (addr->state != MBLTY_INTF_ADDR_STATE_NOINFO)
			flags |= KERN_ADDR_F_REPLACE;

		linux_intf_address_add(addr->intf, addr->address, flags,
				       linux_addr_added, addr);
	}

	addr->pending = addr->newstate = newstate;
}

void
mblty_intf_addr_remove(mblty_intf_addr_t *addr)
{
	if (addr->state != addr->newstate)
		linux_intf_cancel_addr_op(addr->intf, addr);

	if (addr->state != MBLTY_INTF_ADDR_STATE_NOINFO) {
		list_del(&addr->entry);

		linux_intf_address_remove(addr->intf, addr->address,
					  NULL, NULL);
	}

	addr->state = MBLTY_INTF_ADDR_STATE_NOINFO;
}

static void
policy_added(int result, void *param)
{
	mblty_policy_t *pol = param;

	if (result == 0)
		pol->state = MBLTY_POLICY_STATE_OK;
	else
		pol->state = MBLTY_POLICY_STATE_FAILED;

	if (pol->ops)
		pol->ops->added(pol, result);
}

static void
pol_kern_op(int add, mblty_policy_t *pol, void (*cb)(int, void *))
{
	int metric = KERN_DEF_METRIC;

	if (add)
		linux_route_add(pol->destination, pol->source, pol->gateway,
			        pol->intf, metric, pol->flags, cb, pol);
	else
		linux_route_delete(pol->destination, pol->source, pol->gateway,
				   pol->intf, metric, cb, pol);
}

void
mblty_init_policy(mblty_policy_t *pol)
{
	pol->state = MBLTY_POLICY_STATE_UNKNOWN;
	pol->flags = 0;

	pol->destination = NULL;
	pol->source = NULL;
	pol->intf = NULL;
	pol->gateway = NULL;
}

void
mblty_fill_policy(mblty_policy_t *pol, struct in6_prefix *dst,
		  mblty_network_address_t *addr)
{
	pol->destination = dst;
	pol->source = mblty_get_addr(addr);
	pol->intf = mblty_addr_intf(addr)->osh;
	pol->gateway = mblty_rtr_address(mblty_addr_router(addr));
	pol->flags = 0;
}

void
mblty_add_policy(mblty_policy_t *pol)
{
	pol->state = MBLTY_POLICY_STATE_INSTALLING;
	pol_kern_op(1, pol, policy_added);
}

void
mblty_delete_policy(mblty_policy_t *pol)
{
	if (pol->state == MBLTY_POLICY_STATE_INSTALLING) {
		linux_cancel_request(pol);
	} else if (pol->state == MBLTY_POLICY_STATE_OK) {
		pol_kern_op(0, pol, NULL);
	}

	pol->state = MBLTY_POLICY_STATE_UNKNOWN;
}

void
mblty_copy_policy(mblty_policy_t *dst, mblty_policy_t *src)
{
	dst->destination = src->destination;
	dst->source = src->source;
	dst->intf = src->intf;
	dst->gateway = src->gateway;

	dst->flags = src->flags;
	dst->state = src->state;
	dst->ops = src->ops;

	if (dst->state == MBLTY_POLICY_STATE_INSTALLING) {
		struct linux_pending_msg *req;

		req = linux_get_request(policy_added, src);
		debug_assert(req, "Policy is still Installing?");

		req->param = dst;
	}

	src->state = MBLTY_POLICY_STATE_UNKNOWN;
}

