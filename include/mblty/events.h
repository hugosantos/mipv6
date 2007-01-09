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

#ifndef _MBLTY_EVENTS_H_
#define _MBLTY_EVENTS_H_

#include <stdint.h>

#include <mblty/base-defs.h>

struct mblty_event_ops {
	void (*found_interface)(mblty_os_intf_t *);

	void (*interface_event)(mblty_interface_t *, int ev);

	void (*address_added)(mblty_os_intf_t *, struct in6_prefix *);
	void (*address_removed)(mblty_os_intf_t *, struct in6_prefix *);

	void (*address_available)(mblty_network_address_t *);
	void (*address_lost)(mblty_network_address_t *);

	void (*added_network_prefix)(mblty_router_prefix_t *);
	void (*linked_router)(mblty_router_t *);
};

void mblty_found_interface(mblty_os_intf_t *);
void mblty_lost_interface(mblty_os_intf_t *);
void mblty_interface_flags_changed(mblty_os_intf_t *, uint32_t);
void mblty_interface_event(mblty_interface_t *, int ev);
void mblty_interface_added_network_prefix(mblty_router_prefix_t *);
void mblty_linked_router(mblty_router_t *);
void mblty_address_added(mblty_os_intf_t *, struct in6_prefix *);
void mblty_address_removed(mblty_os_intf_t *, struct in6_prefix *);
void mblty_address_available(mblty_network_address_t *);
void mblty_address_lost(mblty_network_address_t *);

extern struct mblty_event_ops *mblty_global_events;

#endif /* _MBLTY_EVENTS_H_ */
