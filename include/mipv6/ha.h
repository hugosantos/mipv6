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

#ifndef _MIPV6_PRIV_HA_H_
#define _MIPV6_PRIV_HA_H_

#include <mblty/ndisc.h>
#include <mblty/tunnel.h>

#include <mipv6/protocol.h> /* for mipv6_bcache_entry_data */

struct mblty_interface;

struct mipv6_home_prefix {
	struct in6_addr ha_addr;

	struct in6_prefix pfx;

	struct mblty_interface *intf;

	int usecount;

	struct list_entry entry;
};

struct mipv6_ha_bcache_entry {
	struct mipv6_bcache_entry bce;

	struct mblty_tunnel *tun;

	struct mipv6_home_prefix *homepfx;

#define MIPV6_HA_BC_UNKNOWN		0
#define MIPV6_HA_BC_ROUTE_PENDING	1
#define MIPV6_HA_BC_STABLE		2
	int state;

	ndisc_address_record_t nar;
	mblty_policy_t hostroute;
};

#define HA_BCE(entry) \
	container_of(entry, struct mipv6_ha_bcache_entry, bce)

struct mipv6_home_prefix *mipv6_matching_home_prefix(struct in6_addr *);

#endif /* _MIPV6_PRIV_HA_H_ */
