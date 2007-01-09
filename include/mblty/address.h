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

#ifndef _MBLTY_ADDRESS_H_
#define _MBLTY_ADDRESS_H_

#include <netinet/in.h>

#include <mblty/ndisc.h>
#include <mblty/policy.h>
#include <mblty/timers.h>
#include <mblty/base-defs.h>
#include <mblty/list-support.h>

struct mblty_address {
	struct in6_addr address;
	int refcount;
	struct list_entry entry;
};

struct mblty_network_address_ops {
	/* called during the initial destructor phase */
	void    (*removing)(mblty_network_address_t *);
	/* called to destroy the allocated network address. if
	 * not specified, the network address is free_object()'ed */
	void  (*destructor)(mblty_network_address_t *);
	/* triggered when the parent router is again reachable */
	void   (*reachable)(mblty_network_address_t *);
	/* triggered when the parent router is marked as
	 * unreachable. for instance during a link-down event */
	void (*unreachable)(mblty_network_address_t *);
};

struct mblty_addr_category {
	const char *name;
	int (*preference)(mblty_network_address_t *);
	struct list_entry entry;
};

struct mblty_base_address {
	mblty_address_t *parent;
	mblty_interface_t *intf;
	int refcount;
	struct list_entry entry;
};

typedef enum {
	MBLTY_INTF_ADDR_STATE_NOINFO	= 0,
	MBLTY_INTF_ADDR_STATE_READY,
	MBLTY_INTF_ADDR_STATE_TENTATIVE,
	MBLTY_INTF_ADDR_STATE_DEPRECATED,
} mblty_intf_addr_state_t;

struct mblty_intf_addr_ops {
	void (*changed_state)(mblty_intf_addr_t *, mblty_intf_addr_state_t);
};

struct mblty_intf_addr {
	mblty_os_intf_t *intf;
	struct in6_addr *address;
#define MBLTY_INTF_ADDR_F_HOME_ADDRESS	0x0001
#define MBLTY_INTF_ADDR_F_MANAGED	0x0002
	uint32_t flags;
	mblty_intf_addr_state_t state, newstate, pending;
	mblty_intf_addr_ops_t *ops;
	struct list_entry entry;
};

struct mblty_managed_interest_ops {
	/* called when the associated address was claimed */
	void (*available)(mblty_managed_interest_t *);
	/* called when the address is no longer claimed,
	 * for instance after a link down */
	void (*lost)(mblty_managed_interest_t *, int rechecking);
	/* called if claiming (for instance through DAD)
	 * the address fails */
	void (*failed)(mblty_managed_interest_t *);
};

struct mblty_managed_interest {
	mblty_managed_interest_ops_t *ops;
	struct list_entry entry;
};

typedef enum {
	MBLTY_MMA_STATE_NOINFO = 0,
	MBLTY_MMA_STATE_INSTALLING,
	MBLTY_MMA_STATE_RECHECKING,
	MBLTY_MMA_STATE_CLAIMING,
	MBLTY_MMA_STATE_CLAIMED,
	MBLTY_MMA_STATE_INS_LINK_ROUTE,
	MBLTY_MMA_STATE_READY,
	MBLTY_MMA_STATE_DAD_FAILED,
} mblty_managed_addr_state_t;

struct mblty_managed_addr {
	mblty_base_address_t *base;
	mblty_intf_addr_t inst;
	ndisc_address_record_t nar;

	struct list_entry interest;

#define MBLTY_MMA_F_RUNNING	0x1000
#define MBLTY_MMA_F_HADCLAIMED	0x2000
#define MBLTY_MMA_F_ALIVE	0x4000
	uint32_t flags;

	mblty_managed_addr_state_t state;

	mblty_prefix_t *prefix;
	mblty_policy_t linkroute;

	struct list_entry entry;
};

struct mblty_network_address {
	mblty_base_address_t *base;

	mblty_addr_category_t *category;
	mblty_router_prefix_t *prefix;
	mblty_network_address_ops_t *ops;

	/* linked-list handle used with mblty_router_prefix's addresses list */
	struct list_entry entry;
};

struct mblty_prefix {
	struct in6_prefix prefix;
	int refcount;
	struct list_entry entry;
};

struct mblty_intf_prefix {
	mblty_prefix_t *parent;

	/* list of mblty_router_prefixes */
	struct list_entry instances;

	struct list_entry entry;
};

struct mblty_router_prefix {
	mblty_intf_prefix_t *parent;

	mblty_router_t *owner;

/* the router says no DAD required for this prefix */
#define MBLTY_NETPFX_NO_DAD		0x0001
/* no addresses should be generated from this prefix */
#define MBLTY_NETPFX_NO_AUTOCONF	0x0002
/* this prefix is available only for a finite ammount of time */
#define MBLTY_NETPFX_TEMPORARY		0x0004
#define MBLTY_NETPFX_ONLINK		0x1000
	uint32_t flags;

	suptimer_t timer;

	void (*address_available)(mblty_managed_address_t *);

	struct list_entry addresses;

	struct list_entry entry, instance;
};

struct mblty_link_local {
	mblty_base_address_t *base;
	mblty_managed_interest_t mginter;
	mblty_managed_addr_t *mgaddr;
#define MBLTY_LL_F_READY	0x0001
	uint32_t flags;
	struct list_entry entry;
};

struct mblty_unicast_address {
	mblty_network_address_t base;

	mblty_managed_interest_t mginter;
	mblty_managed_addr_t *mgaddr;

	enum {
		MBLTY_UNI_STATE_NOINFO = 0,
		MBLTY_UNI_STATE_INS_DEF_ROUTE,
		MBLTY_UNI_STATE_FULL_REACH,
	} state;

	int preference;

#define MBLTY_UNI_F_RTREACHABLE	0x0001
	uint32_t flags;

	mblty_policy_t defroute;
};

void mblty_intf_addr_init(mblty_intf_addr_t *, mblty_os_intf_t *,
			  struct in6_addr *);
void mblty_intf_addr_change_to(mblty_intf_addr_t *, mblty_intf_addr_state_t);
void mblty_intf_addr_remove(mblty_intf_addr_t *);

/* Layer 2 address */
struct mblty_link_addr {
	uint8_t *addr;
	int length;
};

static inline struct in6_addr *
mblty_get_base_addr(mblty_base_address_t *addr)
{
	if (addr == NULL)
		return NULL;
	return &addr->parent->address;
}

static inline struct mblty_interface *
mblty_base_addr_intf(mblty_base_address_t *addr)
{
	return addr->intf;
}

static inline struct in6_addr *
mblty_get_addr(mblty_network_address_t *addr)
{
	if (addr == NULL)
		return NULL;
	return mblty_get_base_addr(addr->base);
}

static inline mblty_address_t *
mblty_addr_parent(mblty_network_address_t *addr)
{
	if (addr == NULL)
		return NULL;
	return addr->base->parent;
}

static inline struct in6_prefix *
mblty_get_rtr_pfx(mblty_router_prefix_t *pfx)
{
	return &pfx->parent->parent->prefix;
}

static inline struct in6_prefix *
mblty_get_pfx(mblty_network_address_t *addr)
{
	return mblty_get_rtr_pfx(addr->prefix);
}

static inline struct mblty_interface *
mblty_addr_intf(mblty_network_address_t *addr)
{
	if (addr == NULL)
		return NULL;
	return mblty_base_addr_intf(addr->base);
}

static inline struct mblty_router *
mblty_addr_router(mblty_network_address_t *addr)
{
	if (addr == NULL || addr->prefix == NULL)
		return NULL;
	return addr->prefix->owner;
}

static inline int
mblty_addr_preference(mblty_network_address_t *addr)
{
	if (addr->category->preference)
		return addr->category->preference(addr);
	return 0;
}

static inline struct mblty_router *
mblty_pfx_router(struct mblty_router_prefix *pfx)
{
	return pfx->owner;
}

static inline int
mblty_same_addr(mblty_network_address_t *a1, mblty_network_address_t *a2)
{
	if (a1 == NULL || a2 == NULL)
		return 0;
	return a1->base->parent == a2->base->parent;
}

static inline int
mblty_same_prefix(mblty_network_address_t *a1, mblty_network_address_t *a2)
{
	if (a1 == NULL || a2 == NULL)
		return 0;
	return a1->prefix->parent->parent == a2->prefix->parent->parent;
}

int mblty_init_address(mblty_network_address_t *, struct in6_addr *addr,
		       mblty_addr_category_t *, mblty_router_prefix_t *,
		       mblty_network_address_ops_t *ops);
void mblty_deinit_address(mblty_network_address_t *);
void mblty_remove_address(mblty_network_address_t *);

/* grab address reference */
mblty_address_t *mblty_get_address(mblty_address_t *);
mblty_address_t *mblty_hard_get_address(struct in6_addr *);
/* release address reference. If the number of references
 * reaches zero, the address resources are released */
void mblty_put_address(mblty_address_t *);

mblty_link_addr_t *mblty_alloc_link_addr(uint8_t *addr, int len);
void mblty_release_link_addr(mblty_link_addr_t *);
int mblty_compare_link_addr(mblty_link_addr_t *, uint8_t *, int);

void mblty_register_addr_category(mblty_addr_category_t *);
mblty_addr_category_t *mblty_get_addr_category_by_name(const char *);

mblty_prefix_t *mblty_retrieve_prefix(struct in6_prefix *);
mblty_prefix_t *mblty_get_prefix(struct in6_prefix *, mblty_intf_prefix_t *);
void mblty_put_prefix(mblty_prefix_t *);

void mblty_clear_interface_linklocals(mblty_interface_t *);
void mblty_clear_prefix_addresses(mblty_router_prefix_t *,
				  mblty_addr_category_t *);
void mblty_prefix_update_lifetimes(mblty_router_prefix_t *, uint32_t valid,
				   uint32_t preferred);

void mblty_foreach_address(void (*)(mblty_address_t *, void *), void *);
void mblty_foreach_prefix(void (*)(mblty_prefix_t *, void *), void *);

mblty_base_address_t *mblty_obtain_address(mblty_interface_t *,
					   struct in6_addr *);
void mblty_drop_address(mblty_base_address_t *);
int mblty_has_address(mblty_interface_t *, struct in6_addr *);

mblty_managed_addr_t *mblty_managed_addr_obtain(mblty_interface_t *,
						mblty_prefix_t *,
						struct in6_addr *);
void mblty_managed_addr_link(mblty_managed_addr_t *,
			     mblty_managed_interest_t *);
void mblty_managed_addr_unlink(mblty_managed_addr_t *,
			       mblty_managed_interest_t *);
void mblty_managed_addr_proceed(mblty_managed_addr_t *);
void mblty_managed_addr_recheck(mblty_managed_addr_t *);
int mblty_is_addr_available(mblty_managed_addr_t *);

mblty_link_local_t *mblty_allocate_linklocal(mblty_interface_t *,
					     struct in6_addr *, int managed);
void mblty_link_linklocal(mblty_link_local_t *);
void mblty_unlink_linklocal(mblty_link_local_t *);
void mblty_remove_linklocal(mblty_link_local_t *);

mblty_network_address_t *mblty_prefix_get_address(mblty_router_prefix_t *,
						  struct in6_addr *);

#endif /* _MBLTY_ADDRESS_H_ */
