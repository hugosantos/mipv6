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

#ifndef _MBLTY_PRIV_INTERFACE_H_
#define _MBLTY_PRIV_INTERFACE_H_

#include <stdint.h>

#include <mblty/router.h>
#include <mblty/list-support.h>

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

struct mblty_eui64 {
	uint8_t data[8];
};

typedef enum {
	/* interface got link */
	MBLTY_INTF_EV_LINK_UP	= 1,
	/* interface lost link */
	MBLTY_INTF_EV_LINK_DOWN	= 2,
	/* interface is going up */
	MBLTY_INTF_EV_UP	= 3,
	/* interface is going down */
	MBLTY_INTF_EV_DOWN	= 4,
	/* interface being removed */
	MBLTY_INTF_EV_REMOVING	= 5,
	/* interface has a link local addr available now */
	MBLTY_INTF_EV_LL_AVAIL	= 6,
	/* all link locals have been lost */
	MBLTY_INTF_EV_LL_LOST	= 7,
	MBLTY_INTF_EV_PREP	= 8,
	MBLTY_INTF_EV_DELETED	= 9,
} mblty_intf_event_t;

typedef enum {
	MBLTY_OS_INTF_CAP_FORWARDING	= 1,
	MBLTY_OS_INTF_CAP_AUTOCONF	= 2,
} mblty_os_intf_cap_t;

struct mblty_os_intf_ops {
	const char *(*description)(mblty_os_intf_t *, int longdesc,
				   char *, size_t);

	int (*get_type)(mblty_os_intf_t *);
	int (*get_address)(mblty_os_intf_t *, uint8_t *, size_t);
	int (*get_flags)(mblty_os_intf_t *, uint32_t *);
	int (*set_up)(mblty_os_intf_t *, int);

	int (*neigh_update)(mblty_os_intf_t *, struct in6_addr *,
			    uint8_t *, size_t addrlen);

	int (*enable)(mblty_os_intf_t *, mblty_os_intf_cap_t);
	int (*disable)(mblty_os_intf_t *, mblty_os_intf_cap_t);
};

struct mblty_os_intf {
	char name[IFNAMSIZ];

	mblty_os_intf_ops_t *ops;
};

struct mblty_interface {
	mblty_os_intf_t *osh;

	mblty_eui64_t eui64;

	int refcount;

/* interface is up */
#define MBLTY_INTF_HAS_EUI64		0x0001
/* link-up event is being delayed due to
 * buggy event source (driver) */
#define MBLTY_INTF_WARMING_UP		0x0002
	uint32_t flags;

	uint32_t os_flags;

	int warm_up;
	suptimer_t warm_up_timer;

	/* static preference between interfaces */
	int preference;

	struct mblty_autoconf_strategy *autoconf;
	struct mblty_autoconf_data *autoconf_data;
	mblty_router_ops_t *def_router_ops;

	struct list_entry linklocals;
	struct list_entry addresses;
	struct list_entry prefixes;
	struct list_entry managed;
	struct list_entry routers;
	struct list_entry router_names;

	struct list_entry entry;
};

mblty_interface_t *mblty_create_interface(mblty_os_intf_t *, int cost,
					  int skip);

mblty_interface_t *__mblty_get_interface(mblty_os_intf_t *);
mblty_interface_t *mblty_get_interface(mblty_os_intf_t *);
mblty_interface_t *mblty_grab_interface(mblty_interface_t *);
void mblty_put_interface(mblty_interface_t *);

int mblty_has_interface(mblty_os_intf_t *);
int mblty_interface_has_link(mblty_interface_t *);

void mblty_interface_set_eui64(mblty_interface_t *, mblty_eui64_t *);

mblty_intf_prefix_t *mblty_retrieve_intf_prefix(mblty_interface_t *,
						struct in6_prefix *);
mblty_intf_prefix_t *mblty_intf_get_prefix(mblty_interface_t *,
					   struct in6_prefix *,
					   mblty_router_prefix_t *);
void mblty_intf_put_prefix(mblty_interface_t *, mblty_router_prefix_t *);

int mblty_linklocal_for(mblty_interface_t *, struct in6_addr *daddr,
			struct in6_addr *saddr);
mblty_link_local_t *mblty_get_linklocal(mblty_interface_t *intf,
					struct in6_addr *addr);

int mblty_interface_count();

void mblty_clear_interfaces();

/* function retrieves router from known routers or instantiates a new one */
mblty_router_t *mblty_intf_get_router(mblty_interface_t *,
				      struct in6_addr *);
mblty_router_t *mblty_alloc_router(mblty_interface_t *, struct in6_addr *,
				   mblty_router_ops_t *);

void mblty_foreach_interface(void (*)(mblty_interface_t *, void *), void *);

/* os intf methods */
mblty_os_intf_t *mblty_os_intf_get_by_name(const char *);
mblty_os_intf_t *mblty_os_intf_get_loopback();
int mblty_os_intf_is_loopback(mblty_os_intf_t *);

const char *mblty_os_intf_desc(mblty_os_intf_t *, int longd, char *, size_t);
int mblty_os_intf_get_type(mblty_os_intf_t *);
int mblty_os_intf_get_flags(mblty_os_intf_t *, uint32_t *);
int mblty_os_intf_get_address(mblty_os_intf_t *, uint8_t *, size_t);
int mblty_os_intf_neigh_update(mblty_os_intf_t *, struct in6_addr *,
			       uint8_t *, size_t);
int mblty_os_intf_set_up(mblty_os_intf_t *, int);
int mblty_os_intf_enable(mblty_os_intf_t *, mblty_os_intf_cap_t);
int mblty_os_intf_disable(mblty_os_intf_t *, mblty_os_intf_cap_t);

void mblty_os_intf_get_addresses(mblty_os_intf_t *, void (*)(mblty_os_intf_t *,
				 struct in6_prefix *, void *), void *);

void mblty_os_intf_remove_kernel_addresses(mblty_os_intf_t *);
void mblty_os_intf_remove_kernel_routes(mblty_os_intf_t *);

#endif /* _MBLTY_PRIV_INTERFACE_H_ */
