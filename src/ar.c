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

#include <mblty/ndisc.h>
#include <mblty/events.h>
#include <mblty/icmpv6.h>
#include <mblty/autoconf.h>
#include <mblty/interface.h>
#include <mblty/base-support.h>

static void ar_interface_event(struct mblty_interface *, int);
static void ar_address_added(mblty_os_intf_t *, struct in6_prefix *);
static void ar_address_removed(mblty_os_intf_t *, struct in6_prefix *);

static LIST_DEF(home_pfxs);

static struct support_debug_conf dbg_conf = {
	.log_file = "mob6-ar.log",
	.log_level = 15,
};

static ndisc_conf_t ndisc_conf = NDISC_DEFAULT_CONF;

static struct mblty_event_ops ar_event_ops = {
	.interface_event = ar_interface_event,
	.address_added = ar_address_added,
	.address_removed = ar_address_removed,
};

static mblty_router_t *
self_router(mblty_interface_t *intf)
{
	struct in6_addr selfaddr;

	mblty_linklocal_for(intf, NULL, &selfaddr);

	return mblty_intf_get_router(intf, &selfaddr);
}

static mblty_interface_t *
check_addr_get_intf(mblty_os_intf_t *osh, struct in6_prefix *p)
{
	if (p->prefixlen == 128)
		return NULL;

	if (memcmp(&p->address, &in6addr_loopback, 16) == 0)
		return NULL;

	return mblty_get_interface(osh);
}

static void
ar_address_op(mblty_os_intf_t *osh, struct in6_prefix *p, int add)
{
	mblty_interface_t *intf = check_addr_get_intf(osh, p);
	struct in6_addr *ptr = &p->address;
	mblty_network_address_t *addr;
	mblty_router_prefix_t *pfx;
	struct in6_prefix tmp;

	if (intf == NULL)
		return;

	if (IN6_IS_ADDR_LINKLOCAL(&p->address)) {
		mblty_link_local_t *linklocal = mblty_get_linklocal(intf, ptr);

		if (add && !linklocal) {
			linklocal = mblty_allocate_linklocal(intf, ptr, 0);
			if (linklocal)
				mblty_link_linklocal(linklocal);
		} else if (!addr && linklocal) {
			mblty_remove_linklocal(linklocal);
		}

		mblty_put_interface(intf);
		return;
	}

	in6_prefix_copy_applied(&tmp, p);

	pfx = mblty_router_get_prefix(self_router(intf), &tmp);
	if (pfx == NULL && add)
		pfx = mblty_router_announced_prefix(self_router(intf),
						    &tmp, 0);

	if (pfx) {
		addr = mblty_prefix_get_address(pfx, ptr);

		if (add && addr == NULL) {
			addr = allocate_object(mblty_network_address_t);
			mblty_init_address(addr, ptr, NULL, pfx, NULL);
		} else if (!addr && addr != NULL) {
			mblty_remove_address(addr);
		}
	}

	mblty_put_interface(intf);
}

static void
ar_address_added(mblty_os_intf_t *osh, struct in6_prefix *p)
{
	ar_address_op(osh, p, 1);
}

static void
ar_address_removed(mblty_os_intf_t *osh, struct in6_prefix *p)
{
	ar_address_op(osh, p, 0);
}

static void
ar_populate_intf(mblty_os_intf_t *osh, struct in6_prefix *addr, void *arg)
{
	ar_address_added(osh, addr);
}

struct l_address {
	struct in6_prefix address;
	struct list_entry entry;
};

static void
ar_get_ll(mblty_os_intf_t *osh, struct in6_prefix *addr, void *param)
{
	struct list_entry *list = param;
	struct l_address *laddr;

	if (!IN6_IS_ADDR_LINKLOCAL(&addr->address))
		return;

	laddr = allocate_object(struct l_address);
	if (laddr == NULL)
		return;

	in6_prefix_copy(&laddr->address, addr);
	list_add_tail(&laddr->entry, list);
}

static void
ar_populate_lls(mblty_interface_t *intf)
{
	struct l_address *addr, *tmp;
	struct list_entry l;

	list_init(&l);
	/* we must copy here as we can't nest get_addresses calls
	 * and adding the first link local will trigger LL_AVAIL */
	mblty_os_intf_get_addresses(intf->osh, ar_get_ll, &l);

	list_for_each_entry_safe (addr, tmp, &l, entry) {
		ar_address_added(intf->osh, &addr->address);
		list_del(&addr->entry);
		free_object(addr);
	}
}

static void
ar_interface_event(mblty_interface_t *intf, int event)
{
	mblty_router_t *rtr, *tmp;
	struct in6_addr selfaddr;

	switch (event) {
	case MBLTY_INTF_EV_UP:
		ar_populate_lls(intf);
		break;

	case MBLTY_INTF_EV_LL_AVAIL:
		mblty_linklocal_for(intf, NULL, &selfaddr);
		mblty_alloc_router(intf, &selfaddr, NULL);
		mblty_os_intf_get_addresses(intf->osh, ar_populate_intf, NULL);
		break;

	case MBLTY_INTF_EV_LL_LOST:
		list_for_each_entry_safe (rtr, tmp, &intf->routers, entry) {
			mblty_remove_router(rtr);
		}
		break;
	}
}

int
main(int argc, char *argv[])
{
	mblty_init_program(&dbg_conf, &ar_event_ops);

	icmpv6_protocol_init();
	ndisc_init(&ndisc_conf);
	mblty_autoconf_init();

	mblty_create_interface(mblty_os_intf_get_by_name("eth0"), 0, 0);

	return mblty_main_loop();
}

