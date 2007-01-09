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

#ifndef _MBLTY_SOURCE_ROUTE_H_
#define _MBLTY_SOURCE_ROUTE_H_

#include <mblty/base-defs.h>
#include <mblty/list-support.h>

typedef struct mblty_policy mblty_policy_t;
typedef struct mblty_policy_ops mblty_policy_ops_t;

struct mblty_network_address;

struct mblty_policy {
	/* selection tuple (dst, src) */
	struct in6_prefix *destination;
	struct in6_addr *source;

	/* exit via (intf, gw) */
	struct mblty_os_intf *intf;
	struct in6_addr *gateway;

#define MBLTY_POLICY_F_NOTIFY		0x0100
	uint32_t flags;

	enum {
		MBLTY_POLICY_STATE_FAILED = -1,
		MBLTY_POLICY_STATE_UNKNOWN = 0,
		MBLTY_POLICY_STATE_INSTALLING = 1,
		MBLTY_POLICY_STATE_OK = 2,
	} state;

	mblty_policy_ops_t *ops;
};

struct mblty_policy_ops {
	void (*added)(mblty_policy_t *, int res);
};

void mblty_init_policy(mblty_policy_t *);
void mblty_fill_policy(mblty_policy_t *, struct in6_prefix *dst,
		       struct mblty_network_address *);

void mblty_add_policy(mblty_policy_t *);
void mblty_delete_policy(mblty_policy_t *);
void mblty_copy_policy(mblty_policy_t *target, mblty_policy_t *origin);

#endif

