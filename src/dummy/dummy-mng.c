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

void
mblty_intf_addr_change_to(mblty_intf_addr_t *addr,
			  mblty_intf_addr_state_t newstate)
{
}

void
mblty_intf_addr_remove(mblty_intf_addr_t *addr)
{
	addr->state = MBLTY_INTF_ADDR_STATE_NOINFO;
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
}

void
mblty_delete_policy(mblty_policy_t *pol)
{
	if (pol->state == MBLTY_POLICY_STATE_INSTALLING) {
	} else if (pol->state == MBLTY_POLICY_STATE_OK) {
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
	}

	src->state = MBLTY_POLICY_STATE_UNKNOWN;
}

