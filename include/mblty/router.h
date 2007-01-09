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

#ifndef _MBLTY_PRIV_ROUTER_H_
#define _MBLTY_PRIV_ROUTER_H_

#include <netinet/in.h> /* for struct in6_addr */

#include <mblty/reach.h>
#include <mblty/timers.h>
#include <mblty/address.h>
#include <mblty/base-defs.h>
#include <mblty/list-support.h>

struct mblty_router_ops {
	void        (*remove)(mblty_router_t *);
	void      (*removing)(mblty_router_t *);
	void     (*link_down)(mblty_router_t *);
	void (*flags_changed)(mblty_router_t *, uint32_t old_flags);
};

struct mblty_router_name {
	mblty_interface_t *intf;
	/* router's address */
	struct in6_addr address;

#define MBLTY_RTRNAME_ALIAS	0x0001
	uint32_t flags;

	mblty_router_t *instance;

	struct list_entry entry, name_entry;
};

struct mblty_router {
	mblty_router_name_t name;

	mblty_link_addr_t *link_addr;

/* this router may not be a defaulr router in the future */
#define MBLTY_ROUTER_RUNNING_DEFAULT	0x0001
/* this router's prefix information is managed (stateful) */
#define MBLTY_ROUTER_MANAGED		0x0002
/* this router is an home agent */
#define MBLTY_ROUTER_HOME_AGENT		0x0004
#define MBLTY_ROUTER_IS_LINKED		0x0100
	uint32_t flags;

	int use_count;

	/* timer associated with the Default router status */
	suptimer_t default_timer;

	/* list of network prefixes advertised by this router */
	struct list_entry prefixes;

	mblty_router_ops_t *ops;

	struct mblty_reach_data *reach;

	struct list_entry names;

	/* the router structure is linked in the global router list */
	struct list_entry rtrs;
	/* link the router to the interface */
	struct list_entry entry;
};

static inline mblty_interface_t *
mblty_rtr_intf(mblty_router_t *rtr)
{
	return rtr->name.intf;
}

static inline struct in6_addr *
mblty_rtr_address(mblty_router_t *rtr)
{
	return &rtr->name.address;
}

static inline mblty_interface_t *
mblty_pfx_intf(mblty_router_prefix_t *pfx)
{
	if (pfx->owner == NULL)
		return NULL;
	return mblty_rtr_intf(pfx->owner);
}

mblty_router_t *mblty_init_router(mblty_router_t *, mblty_interface_t *,
				  struct in6_addr *, mblty_router_ops_t *,
				  int linkto);
void mblty_deinit_router(mblty_router_t *);
void mblty_remove_router(mblty_router_t *);
mblty_router_name_t *mblty_add_router_alias(mblty_router_t *,
					    struct in6_addr *);

void mblty_router_flags_changed(mblty_router_t *, uint32_t oldflags);

/* if lifetime is zero, the router is no longer a default router */
void mblty_update_router_lifetime(mblty_router_t *, int lifetime);

void mblty_link_router(struct mblty_interface *, mblty_router_t *);
void mblty_unlink_router(mblty_router_t *);

void mblty_using_router(mblty_router_t *, int inc);

mblty_router_prefix_t *mblty_router_get_prefix(mblty_router_t *,
					       struct in6_prefix *);
mblty_router_prefix_t *mblty_router_announced_prefix(mblty_router_t *,
						     struct in6_prefix *, uint32_t);
void mblty_router_remove_prefix(mblty_router_prefix_t *);

void mblty_router_set_link_addr(mblty_router_t *, uint8_t *, int);

void mblty_foreach_router(void (*)(mblty_router_t *, void *), void *);

void mblty_setup_router_reachability(mblty_router_t *);
int mblty_is_router_reachable(mblty_router_t *);

#endif /* _MBLTY_PRIV_ROUTER_H_ */
