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

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/socket.h>
#include <net/if.h> /* for if_nametoindex() */
#include <net/if_arp.h> /* for ARPHRD_ETHER */
#include <netinet/in.h>

#include <mblty/events.h>
#include <mblty/autoconf.h>
#include <mblty/interface.h>
#include <mblty/base-support.h>

static LIST_DEF(interfaces);

static void
generate_eui64(mblty_eui64_t *eui64, uint8_t *lladdr)
{
	eui64->data[0] = lladdr[0] | 0x2;
	eui64->data[1] = lladdr[1];
	eui64->data[2] = lladdr[2];
	eui64->data[3] = 0xff;
	eui64->data[4] = 0xfe;
	eui64->data[5] = lladdr[3];
	eui64->data[6] = lladdr[4];
	eui64->data[7] = lladdr[5];
}

static void
_intf_autoconf_event(mblty_interface_t *intf, int ev)
{
	if (intf->autoconf && intf->autoconf->intf_event)
		intf->autoconf->intf_event(intf, ev);
}

static void
mblty_clear_interface_routers(mblty_interface_t *intf, int linkdown)
{
	mblty_router_t *rtr, *tmp;

	mblty_grab_interface(intf);

	list_for_each_entry_safe (rtr, tmp, &intf->routers, entry) {
		if (linkdown) {
			if (rtr->ops && rtr->ops->link_down)
				rtr->ops->link_down(rtr);
		} else {
			mblty_remove_router(rtr);
		}
	}

	mblty_put_interface(intf);
}

static void
trigger_intf_event(mblty_interface_t *intf, int ev)
{
	mblty_managed_addr_t *mma, *tmp;

	_intf_autoconf_event(intf, ev);
	mblty_reach_intf_event(intf->osh, ev);
	mblty_interface_event(intf, ev);

	switch (ev) {
	case MBLTY_INTF_EV_REMOVING:
		mblty_clear_interface_routers(intf, 0);
		mblty_clear_interface_linklocals(intf);
		break;

	case MBLTY_INTF_EV_LINK_UP:
		list_for_each_entry_safe (mma, tmp, &intf->managed, entry) {
			mblty_managed_addr_proceed(mma);
		}
		break;

	case MBLTY_INTF_EV_LINK_DOWN:
		list_for_each_entry_safe (mma, tmp, &intf->managed, entry) {
			mblty_managed_addr_recheck(mma);
		}
		break;
	}
}

static void
intf_warmed_up(mblty_interface_t *intf)
{
	debug_assert(intf->flags & MBLTY_INTF_WARMING_UP,
		     "Interface wasn't warming up.");

	intf->flags &= ~MBLTY_INTF_WARMING_UP;

	trigger_intf_event(intf, MBLTY_INTF_EV_LINK_UP);
}

static void
intf_warmed_up_cb(suptimer_t *timer, void *arg)
{
	intf_warmed_up((mblty_interface_t *)arg);
}

static void
debug_intf_log(mblty_interface_t *intf, int level,
	       const char *fmt, ...)
{
	char buf[128], desc[64];
	va_list vl;

	va_start(vl, fmt);
	vsnprintf(buf, sizeof(buf), fmt, vl);
	va_end(vl);

	debug_log(level, "Interface %s %s\n",
		  mblty_os_intf_desc(intf->osh, 1, desc, sizeof(desc)), buf);
}

static void
intf_end_warmup(mblty_interface_t *intf)
{
	if (intf->flags & MBLTY_INTF_WARMING_UP) {
		intf->flags &= ~MBLTY_INTF_WARMING_UP;
		timer_remove(&intf->warm_up_timer);
	}
}

static void
_mblty_interface_link_changed(mblty_interface_t *intf, int has)
{
	debug_intf_log(intf, 0, "%s link.", has ? "has" : "lost");

	if (has) {
		intf->flags |= MBLTY_INTF_WARMING_UP;

		if (intf->warm_up)
			timer_add(&intf->warm_up_timer, intf->warm_up);
		else
			intf_warmed_up(intf);
	} else {
		intf_end_warmup(intf);
		trigger_intf_event(intf, MBLTY_INTF_EV_LINK_DOWN);
	}
}

static void
_mblty_interface_changed_flags(mblty_interface_t *intf, uint32_t oldflags)
{
	uint32_t flags = intf->os_flags;

	if ((flags & IFF_UP) && !(oldflags & IFF_UP)) {
		debug_intf_log(intf, 0, "going UP.");
		trigger_intf_event(intf, MBLTY_INTF_EV_UP);
	} else if (!(flags & IFF_UP) && (oldflags & IFF_UP)) {
		debug_intf_log(intf, 0, "going DOWN.");
		trigger_intf_event(intf, MBLTY_INTF_EV_DOWN);
		mblty_clear_interface_routers(intf, 1);
	}

	if (!(flags & IFF_UP))
		return;

	if (!(flags & IFF_RUNNING) && (oldflags & IFF_RUNNING)) {
		/* is no longer running */
		_mblty_interface_link_changed(intf, 0);
	} else if ((flags & IFF_RUNNING) && !(oldflags & IFF_RUNNING)) {
		/* is now running */
		_mblty_interface_link_changed(intf, 1);
	}
}

static int
mblty_interface_check_flags(mblty_interface_t *intf)
{
	uint32_t flags;

	if (mblty_os_intf_get_flags(intf->osh, &flags) < 0)
		return -1;

	intf->os_flags = flags;
	_mblty_interface_changed_flags(intf, 0);

	return 0;
}

static mblty_interface_t *
mblty_alloc_interface(mblty_os_intf_t *osh, int cost, int skip)
{
	mblty_interface_t *intf;
	uint8_t lladdr[32];
	const char *type;

	debug_assert(osh, "Missing interface reference");

	intf = allocate_object(struct mblty_interface);

	if (intf == NULL)
		return NULL;

	intf->osh = osh;
	intf->preference = cost;

	intf->flags = 0;
	intf->os_flags = 0;

	switch (mblty_os_intf_get_type(osh)) {
	case ARPHRD_ETHER:
		type = "ethernet";
		if (mblty_os_intf_get_address(osh, lladdr,
					      sizeof(lladdr)) == 6) {
			generate_eui64(&intf->eui64, lladdr);
			intf->flags |= MBLTY_INTF_HAS_EUI64;
		} else {
			debug_intf_log(intf, 2, "Ethernet interface address "
				       "size is not 48-bit?");
		}
		break;
#ifdef ARPHRD_LOOPBACK
	case ARPHRD_LOOPBACK:
		type = "loopback";
		break;
#endif
#ifdef ARPHRD_TUNNEL6
	case ARPHRD_TUNNEL6:
		type = "ip6ip6-tunnel";
		break;
#endif
	default:
		type = "unknown";
		break;
	}

	if (!(intf->flags & MBLTY_INTF_HAS_EUI64))
		memset(&intf->eui64, 0, sizeof(intf->eui64));

	intf->warm_up = 0;
	timer_init_with(&intf->warm_up_timer, "warm up timer",
			intf_warmed_up_cb, intf);

	intf->autoconf = NULL;
	intf->autoconf_data = NULL;
	intf->def_router_ops = NULL;

	list_init(&intf->linklocals);
	list_init(&intf->addresses);
	list_init(&intf->prefixes);
	list_init(&intf->managed);
	list_init(&intf->routers);
	list_init(&intf->router_names);

	intf->refcount = 0;

	list_add_tail(&intf->entry, &interfaces);

	if (intf->flags & MBLTY_INTF_HAS_EUI64) {
		debug_intf_log(intf, 0, "type %s with EUI-64 "
			  "%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X.", type,
			  (int)intf->eui64.data[0], (int)intf->eui64.data[1],
			  (int)intf->eui64.data[2], (int)intf->eui64.data[3],
			  (int)intf->eui64.data[4], (int)intf->eui64.data[5],
			  (int)intf->eui64.data[6], (int)intf->eui64.data[7]);
	} else {
		debug_intf_log(intf, 0, "type %s without EUI-64.", type);
	}

	if (!skip)
		trigger_intf_event(intf, MBLTY_INTF_EV_PREP);

	mblty_interface_check_flags(intf);

	return intf;
}

int
mblty_interface_has_link(mblty_interface_t *intf)
{
	if (intf->flags & MBLTY_INTF_WARMING_UP)
		return 0;
	return intf->os_flags & IFF_RUNNING;
}

void
mblty_lost_interface(mblty_os_intf_t *osh)
{
	mblty_interface_t *intf = mblty_get_interface(osh);

	if (intf) {
		mblty_put_interface(intf);
		/* the second put should delete the interface */
		mblty_put_interface(intf);
	}
}

void
mblty_interface_flags_changed(mblty_os_intf_t *osh, uint32_t flags)
{
	mblty_interface_t *intf = mblty_get_interface(osh);
	uint32_t oldflags;

	if (intf == NULL)
		return;

	oldflags = intf->os_flags;
	intf->os_flags = flags;

	_mblty_interface_changed_flags(intf, oldflags);

	mblty_put_interface(intf);
}

mblty_interface_t *
mblty_grab_interface(mblty_interface_t *intf)
{
	debug_caller(20, "mblty_grab_interface(%s)\n", intf->osh->name);

	if (intf)
		intf->refcount++;
	return intf;
}

mblty_interface_t *
__mblty_get_interface(mblty_os_intf_t *osh)
{
	mblty_interface_t *intf;

	list_for_each_entry (intf, &interfaces, entry) {
		if (intf->osh == osh)
			return intf;
	}

	return NULL;
}

mblty_interface_t *
mblty_get_interface(mblty_os_intf_t *osh)
{
	return mblty_grab_interface(__mblty_get_interface(osh));
}

mblty_interface_t *
mblty_create_interface(mblty_os_intf_t *osh, int cost, int skip)
{
	return mblty_grab_interface(mblty_alloc_interface(osh, cost, skip));
}

static void
mblty_delete_interface(mblty_interface_t *intf)
{
	debug_assert(list_empty(&intf->routers),
		     "Interface still has routers?");

	debug_intf_log(intf, 2, "is being removed.");

	list_del(&intf->entry);

	trigger_intf_event(intf, MBLTY_INTF_EV_DELETED);

	intf_end_warmup(intf);

	/* XXX free all related resources */

	free_object(intf);
}

void
mblty_put_interface(mblty_interface_t *intf)
{
	debug_assert(intf && intf->refcount > 0,
		     "Called mblty_put_interface on bad instance");

	debug_caller(20, "mblty_put_interface(%s)\n", intf->osh->name);

	intf->refcount--;

	if (intf->refcount == 0) {
		mblty_delete_interface(intf);
	}
}

int
mblty_has_interface(mblty_os_intf_t *osh)
{
	return __mblty_get_interface(osh) != NULL;
}

int
mblty_interface_count()
{
	struct list_entry *intf;
	int count = 0;

	list_for_each (intf, &interfaces) {
		count++;
	}

	return count;
}

void
mblty_clear_interfaces()
{
	mblty_interface_t *intf, *tmp;

	list_for_each_entry (intf, &interfaces, entry) {
		mblty_grab_interface(intf);
	}

	list_for_each_entry (intf, &interfaces, entry) {
		uint32_t flags = intf->os_flags;
		intf->os_flags = 0;
		_mblty_interface_changed_flags(intf, flags);
		trigger_intf_event(intf, MBLTY_INTF_EV_REMOVING);
	}

	list_for_each_entry_safe (intf, tmp, &interfaces, entry) {
		/* once for previous grab */
		mblty_put_interface(intf);
		/* another one for the allocation ref */
		mblty_put_interface(intf);
	}

	debug_assert(list_empty(&interfaces),
		     "There are still interface references");
}

void
mblty_remove_router(mblty_router_t *rtr)
{
	if (rtr->ops && rtr->ops->remove) {
		rtr->ops->remove(rtr);
	} else {
		if (rtr->ops && rtr->ops->removing)
			rtr->ops->removing(rtr);
		mblty_deinit_router(rtr);
		free_object(rtr);
	}
}

mblty_router_t *
mblty_alloc_router(mblty_interface_t *intf, struct in6_addr *addr,
		   mblty_router_ops_t *ops)
{
	mblty_router_t *rt = allocate_object(mblty_router_t);

	if (rt == NULL)
		return NULL;

	if (ops == NULL)
		ops = intf->def_router_ops;

	return mblty_init_router(rt, intf, addr, ops, 1);
}

mblty_router_t *
mblty_intf_get_router(mblty_interface_t *intf, struct in6_addr *addr)
{
	mblty_router_name_t *name;

	list_for_each_entry (name, &intf->router_names, entry) {
		if (in6_addr_compare(&name->address, addr) == 0) {
			return name->instance;
		}
	}

	return NULL;
}

mblty_intf_prefix_t *
mblty_retrieve_intf_prefix(mblty_interface_t *intf, struct in6_prefix *ptr)
{
	mblty_intf_prefix_t *intfpfx;

	list_for_each_entry (intfpfx, &intf->prefixes, entry) {
		if (in6_prefix_compare(&intfpfx->parent->prefix, ptr) == 0)
			return intfpfx;
	}

	return NULL;
}

mblty_intf_prefix_t *
mblty_intf_get_prefix(mblty_interface_t *intf, struct in6_prefix *ptr,
		      mblty_router_prefix_t *rtrpfx)
{
	mblty_intf_prefix_t *intfpfx;

	intfpfx = mblty_retrieve_intf_prefix(intf, ptr);
	if (intfpfx == NULL) {
		intfpfx = allocate_object(mblty_intf_prefix_t);
		if (intfpfx == NULL)
			return NULL;

		if (mblty_get_prefix(ptr, intfpfx) == NULL) {
			free_object(intfpfx);
			return NULL;
		}

		list_init(&intfpfx->instances);
		list_add_tail(&intfpfx->entry, &intf->prefixes);
	}

	list_add_tail(&rtrpfx->instance, &intfpfx->instances);
	rtrpfx->parent = intfpfx;

	return intfpfx;
}

void
mblty_intf_put_prefix(mblty_interface_t *intf, mblty_router_prefix_t *rtrpfx)
{
	mblty_intf_prefix_t *parent = rtrpfx->parent;

	list_del(&rtrpfx->instance);
	rtrpfx->parent = NULL;

	if (list_empty(&parent->instances)) {
		mblty_put_prefix(parent->parent);
		parent->parent = NULL;
		list_del(&parent->entry);
		free_object(parent);
	}
}

static int
intf_has_ready_linklocal(mblty_interface_t *intf)
{
	mblty_link_local_t *ll;

	list_for_each_entry (ll, &intf->linklocals, entry) {
		if (ll->flags & MBLTY_LL_F_READY)
			return 0;
	}

	return 1;
}

void
mblty_link_linklocal(mblty_link_local_t *ll)
{
	int wasempty = intf_has_ready_linklocal(ll->base->intf);

	ll->flags |= MBLTY_LL_F_READY;

	if (wasempty)
		trigger_intf_event(ll->base->intf, MBLTY_INTF_EV_LL_AVAIL);
}

void
mblty_unlink_linklocal(mblty_link_local_t *ll)
{
	ll->flags &= ~MBLTY_LL_F_READY;

	if (!intf_has_ready_linklocal(ll->base->intf))
		trigger_intf_event(ll->base->intf, MBLTY_INTF_EV_LL_LOST);
}

int
mblty_linklocal_for(mblty_interface_t *intf, struct in6_addr *daddr,
		    struct in6_addr *saddr)
{
	mblty_link_local_t *ll;

	list_for_each_entry (ll, &intf->linklocals, entry) {
		if (ll->flags & MBLTY_LL_F_READY) {
			in6_addr_copy(saddr, &ll->base->parent->address);
			return 0;
		}
	}

	return -1;
}

mblty_link_local_t *
mblty_get_linklocal(mblty_interface_t *intf, struct in6_addr *addr)
{
	mblty_link_local_t *ll;

	list_for_each_entry (ll, &intf->linklocals, entry) {
		if (in6_addr_compare(addr, &ll->base->parent->address) == 0)
			return ll;
	}

	return NULL;
}

void
mblty_foreach_interface(void (*cb)(mblty_interface_t *, void *), void *cb_arg)
{
	mblty_interface_t *intf;

	list_for_each_entry (intf, &interfaces, entry) {
		cb(intf, cb_arg);
	}
}

void
mblty_interface_set_eui64(mblty_interface_t *intf, mblty_eui64_t *eui64)
{
	memcpy(&intf->eui64, eui64, sizeof(mblty_eui64_t));
	intf->flags |= MBLTY_INTF_HAS_EUI64;
}

const char *
mblty_os_intf_desc(mblty_os_intf_t *osh, int longd, char *buf, size_t buflen)
{
	return osh->ops->description(osh, longd, buf, buflen);
}

int
mblty_os_intf_get_type(mblty_os_intf_t *osh)
{
	return osh->ops->get_type(osh);
}

int
mblty_os_intf_get_flags(mblty_os_intf_t *osh, uint32_t *flags)
{
	return osh->ops->get_flags(osh, flags);
}

int
mblty_os_intf_get_address(mblty_os_intf_t *osh, uint8_t *buf, size_t buflen)
{
	return osh->ops->get_address(osh, buf, buflen);
}

int
mblty_os_intf_neigh_update(mblty_os_intf_t *osh, struct in6_addr *addr,
			   uint8_t *ll, size_t lllen)
{
	if (osh->ops->neigh_update == NULL)
		return -1;
	return osh->ops->neigh_update(osh, addr, ll, lllen);
}

int
mblty_os_intf_set_up(mblty_os_intf_t *osh, int up)
{
	return osh->ops->set_up(osh, up);
}

int
mblty_os_intf_enable(mblty_os_intf_t *osh, mblty_os_intf_cap_t cap)
{
	return osh->ops->enable(osh, cap);
}

int
mblty_os_intf_disable(mblty_os_intf_t *osh, mblty_os_intf_cap_t cap)
{
	return osh->ops->disable(osh, cap);
}

