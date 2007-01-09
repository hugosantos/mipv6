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

#include <mblty/events.h>
#include <mblty/address.h>
#include <mblty/interface.h>

void
mblty_found_interface(mblty_os_intf_t *osh)
{
	if (mblty_global_events->found_interface)
		mblty_global_events->found_interface(osh);
}

void
mblty_interface_event(struct mblty_interface *intf, int ev)
{
	if (mblty_global_events->interface_event)
		mblty_global_events->interface_event(intf, ev);
}

void
mblty_interface_added_network_prefix(struct mblty_router_prefix *pfx)
{
	if (mblty_global_events->added_network_prefix)
		mblty_global_events->added_network_prefix(pfx);
}

void
mblty_linked_router(struct mblty_router *rtr)
{
	if (mblty_global_events->linked_router)
		mblty_global_events->linked_router(rtr);
}

void
mblty_address_available(struct mblty_network_address *addr)
{
	if (mblty_global_events->address_available)
		mblty_global_events->address_available(addr);
}

void
mblty_address_lost(struct mblty_network_address *addr)
{
	if (mblty_global_events->address_lost)
		mblty_global_events->address_lost(addr);
}

