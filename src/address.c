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
#include <mblty/address.h>
#include <mblty/interface.h>
#include <mblty/base-support.h>

static LIST_DEF(addr_categories);
static LIST_DEF(addresses);
static LIST_DEF(prefixes);

static const char *_mgaddr_stname[] = {
	"NoInfo",
	"Installing",
	"Needs recheck",
	"Claiming",
	"Claimed",
	"Installing link route",
	"Ready",
	"DAD Failed",
};

static void mma_ia_changed_state(mblty_intf_addr_t *, mblty_intf_addr_state_t);

static mblty_intf_addr_ops_t mma_ia_ops = {
	.changed_state = mma_ia_changed_state,
};

static void mma_claimed(ndisc_address_record_t *);
static void mma_dad_failed(ndisc_address_record_t *);
static void mma_policy_added(mblty_policy_t *, int res);

static ndisc_address_ops_t mma_ndisc_ops = {
	.claimed = mma_claimed,
	.dad_failed = mma_dad_failed,
};

static mblty_policy_ops_t managed_pol_ops = {
	.added = mma_policy_added,
};

static void linklocal_available(mblty_managed_interest_t *);
static void linklocal_lost(mblty_managed_interest_t *, int willrecheck);
static void linklocal_failed(mblty_managed_interest_t *);

static mblty_managed_interest_ops_t linklocal_interest_ops = {
	.available = linklocal_available,
	.lost = linklocal_lost,
	.failed = linklocal_failed,
};

static mblty_prefix_t *
mblty_grab_prefix(mblty_prefix_t *pfx)
{
	if (pfx)
		pfx->refcount++;
	return pfx;
}

mblty_prefix_t *
mblty_get_prefix(struct in6_prefix *ptr, mblty_intf_prefix_t *intfpfx)
{
	mblty_prefix_t *pfx;

	list_for_each_entry (pfx, &prefixes, entry) {
		if (in6_prefix_compare(&pfx->prefix, ptr) == 0) {
			intfpfx->parent = mblty_grab_prefix(pfx);
			return intfpfx->parent;
		}
	}

	pfx = allocate_object(mblty_prefix_t);
	if (pfx == NULL)
		return NULL;

	in6_prefix_copy(&pfx->prefix, ptr);
	pfx->refcount = 0;
	list_add_tail(&pfx->entry, &prefixes);

	intfpfx->parent = mblty_grab_prefix(pfx);
	return intfpfx->parent;
}

void
mblty_put_prefix(mblty_prefix_t *pfx)
{
	debug_assert(pfx && pfx->refcount > 0,
		     "Consistency problem when releasing prefix");

	pfx->refcount--;
	if (pfx->refcount == 0) {
		list_del(&pfx->entry);
		free_object(pfx);
	}
}

mblty_address_t *
mblty_get_address(mblty_address_t *addr)
{
	if (addr)
		addr->refcount++;
	return addr;
}

void
mblty_put_address(mblty_address_t *addr)
{
	if (addr == NULL)
		return;

	debug_assert(addr->refcount > 0,
		     "Consistency problem when releasing address");

	addr->refcount--;

	if (addr->refcount == 0) {
		/* unlink the address and free it */
		list_del(&addr->entry);
		free_object(addr);
	}
}

static mblty_address_t *
__mblty_get_address(struct in6_addr *address)
{
	mblty_address_t *addr;

	list_for_each_entry (addr, &addresses, entry) {
		if (in6_addr_compare(&addr->address, address) == 0) {
			return addr;
		}
	}

	return NULL;
}

mblty_address_t *
mblty_hard_get_address(struct in6_addr *address)
{
	mblty_address_t *addr;

	addr = __mblty_get_address(address);
	if (addr)
		return mblty_get_address(addr);

	addr = allocate_object(mblty_address_t);
	if (addr == NULL)
		return NULL;

	in6_addr_copy(&addr->address, address);
	addr->refcount = 0;

	list_add_tail(&addr->entry, &addresses);

	return mblty_get_address(addr);
}

void
mblty_address_added(mblty_os_intf_t *osh, struct in6_prefix *addr)
{
	if (mblty_global_events->address_added)
		mblty_global_events->address_added(osh, addr);
}

void
mblty_address_removed(mblty_os_intf_t *osh, struct in6_prefix *addr)
{
	if (mblty_global_events->address_removed)
		mblty_global_events->address_removed(osh, addr);
}

mblty_link_local_t *
mblty_allocate_linklocal(mblty_interface_t *intf, struct in6_addr *addr,
			 int managed)
{
	mblty_link_local_t *ll;

	if (mblty_get_linklocal(intf, addr))
		return NULL;

	ll = allocate_object(mblty_link_local_t);
	if (ll == NULL)
		return NULL;

	ll->base = mblty_obtain_address(intf, addr);
	if (ll->base == NULL) {
		free_object(ll);
		return NULL;
	}

	ll->flags = 0;

	list_add_tail(&ll->entry, &intf->linklocals);

	if (managed) {
		ll->mgaddr = mblty_managed_addr_obtain(intf, NULL, addr);
		if (ll->mgaddr == NULL) {
			mblty_drop_address(ll->base);
			free_object(ll);
			return NULL;
		}

		ll->mginter.ops = &linklocal_interest_ops;
		/* starts the claiming process */
		mblty_managed_addr_link(ll->mgaddr, &ll->mginter);
	} else {
		ll->mgaddr = NULL;
	}

	return ll;
}

void
mblty_remove_linklocal(mblty_link_local_t *ll)
{
	mblty_unlink_linklocal(ll);
	list_del(&ll->entry);
	if (ll->mgaddr)
		mblty_managed_addr_unlink(ll->mgaddr, &ll->mginter);
	mblty_drop_address(ll->base);
	free_object(ll);
}

void
mblty_clear_interface_linklocals(mblty_interface_t *intf)
{
	mblty_link_local_t *ll, *tmp;

	list_for_each_entry_safe (ll, tmp, &intf->linklocals, entry) {
		mblty_remove_linklocal(ll);
	}
}

static mblty_base_address_t *
mblty_intf_get_address(mblty_interface_t *intf, mblty_address_t *par)
{
	mblty_base_address_t *base;

	list_for_each_entry (base, &intf->addresses, entry) {
		if (base->parent == par)
			return base;
	}

	return NULL;
}

static mblty_base_address_t *
mblty_grab_base_addr(mblty_base_address_t *base)
{
	if (base)
		base->refcount++;
	return base;
}

int
mblty_has_address(mblty_interface_t *intf, struct in6_addr *addr)
{
	mblty_address_t *par = __mblty_get_address(addr);
	if (par)
		return mblty_intf_get_address(intf, par) != NULL;
	return 0;
}

mblty_base_address_t *
mblty_obtain_address(mblty_interface_t *intf, struct in6_addr *addr)
{
	mblty_base_address_t *base;
	mblty_address_t *par;

	par = mblty_hard_get_address(addr);
	if (par == NULL)
		return NULL;

	base = mblty_intf_get_address(intf, par);
	if (base == NULL) {
		base = allocate_object(mblty_base_address_t);
		if (base == NULL)
			return NULL;
		base->parent = mblty_get_address(par);
		base->refcount = 0;
		base->intf = mblty_grab_interface(intf);
		list_add_tail(&base->entry, &intf->addresses);
	}

	mblty_put_address(par);

	base->refcount++;
	return base;
}

static void
mblty_destroy_address(mblty_base_address_t *base)
{
	list_del(&base->entry);
	mblty_put_address(base->parent);
	mblty_put_interface(base->intf);
	free_object(base);
}

void
mblty_drop_address(mblty_base_address_t *base)
{
	debug_assert(base && base->refcount > 0, "Consistency issue");

	base->refcount--;
	if (base->refcount == 0)
		mblty_destroy_address(base);
}

void
mblty_deinit_address(mblty_network_address_t *addr)
{
	mblty_drop_address(addr->base);
}

void
mblty_remove_address(mblty_network_address_t *addr)
{
	if (addr->ops && addr->ops->removing)
		addr->ops->removing(addr);

	list_del(&addr->entry);

	mblty_deinit_address(addr);

	if (addr->ops && addr->ops->destructor)
		addr->ops->destructor(addr);
	else
		free_object(addr);
}

void
mblty_clear_prefix_addresses(mblty_router_prefix_t *netpfx,
			     mblty_addr_category_t *cat)
{
	mblty_network_address_t *addr, *tmp;

	/* XXX in order to minimize number of updates, instead
	 * of removing each, we should start a "transaction",
	 * that would lock updates and then release it after
	 * the removal of addresses */

	list_for_each_entry_safe (addr, tmp, &netpfx->addresses, entry) {
		if (cat == NULL || addr->category == cat)
			mblty_remove_address(addr);
	}
}

int
mblty_init_address(mblty_network_address_t *address, struct in6_addr *ptr,
		   mblty_addr_category_t *cat, mblty_router_prefix_t *pfx,
		   mblty_network_address_ops_t *ops)
{
	mblty_interface_t *intf = mblty_pfx_intf(pfx);

	address->base = mblty_obtain_address(intf, ptr);
	if (address->base == NULL)
		return -1;

	address->category = cat;
	address->prefix = pfx;
	address->ops = ops;

	list_add_tail(&address->entry, &pfx->addresses);

	if (ops && ops->reachable &&
	    mblty_is_router_reachable(mblty_pfx_router(pfx)))
		ops->reachable(address);

	return 0;
}

void
mblty_foreach_prefix(void (*cb)(mblty_prefix_t *, void *), void *arg)
{
	mblty_prefix_t *iter;

	list_for_each_entry (iter, &prefixes, entry) {
		cb(iter, arg);
	}
}

void
mblty_foreach_address(void (*cb)(mblty_address_t *, void *), void *arg)
{
	mblty_address_t *iter;

	list_for_each_entry (iter, &addresses, entry) {
		cb(iter, arg);
	}
}

void
mblty_register_addr_category(mblty_addr_category_t *cat)
{
	debug_assert(mblty_get_addr_category_by_name(cat->name) == NULL,
		     "A category is already registered with name %s.",
		     cat->name);

	list_add_tail(&cat->entry, &addr_categories);
}

mblty_addr_category_t *
mblty_get_addr_category_by_name(const char *name)
{
	mblty_addr_category_t *iter;

	list_for_each_entry (iter, &addr_categories, entry) {
		if (strcmp(iter->name, name) == 0)
			return iter;
	}

	return NULL;
}

mblty_link_addr_t *
mblty_alloc_link_addr(uint8_t *addr, int length)
{
	int size = sizeof(mblty_link_addr_t) + length;
	mblty_link_addr_t *ptr;

	ptr = malloc(size);
	if (ptr == NULL)
		return NULL;

	ptr->addr = (uint8_t *)(ptr + 1);
	ptr->length = length;

	memcpy(ptr->addr, addr, length);

	return ptr;
}

void
mblty_release_link_addr(mblty_link_addr_t *addr)
{
	free(addr);
}

int
mblty_compare_link_addr(mblty_link_addr_t *ptr, uint8_t *addr, int len)
{
	if (ptr->length != len)
		return ptr->length - len;

	return memcmp(ptr->addr, addr, len);
}

static void
mma_prepare_prefix(mblty_managed_addr_t *mma, mblty_prefix_t *prefix)
{
	if (prefix == NULL) {
		mma->prefix = NULL;
		return;
	}

	mma->prefix = mblty_grab_prefix(prefix);
	mma->linkroute.destination = &prefix->prefix;
	mma->linkroute.source = &mma->base->parent->address;
	mma->linkroute.intf = mma->base->intf->osh;
	mma->linkroute.gateway = NULL;
	mma->linkroute.ops = &managed_pol_ops;
}

static void
mblty_managed_addr_init(mblty_managed_addr_t *mma, mblty_base_address_t *base,
			mblty_prefix_t *prefix)
{
	mma->base = mblty_grab_base_addr(base);
	mblty_intf_addr_init(&mma->inst, base->intf->osh,
			     &base->parent->address);
	mma->inst.flags = MBLTY_INTF_ADDR_F_MANAGED;
	mma->inst.ops = &mma_ia_ops;
	ndisc_addr_register(&mma->nar, base->intf, base->parent,
			    &mma_ndisc_ops);
	mma->nar.flags = NDISC_ADDRREC_F_NEEDS_DAD;
	list_init(&mma->interest);
	mma->flags = 0;
	mma->state = MBLTY_MMA_STATE_NOINFO;

	mblty_init_policy(&mma->linkroute);
	mma_prepare_prefix(mma, prefix);

	list_add_tail(&mma->entry, &mma->base->intf->managed);
}

static void
mma_change_state(mblty_managed_addr_t *mma, unsigned newstate)
{
	char buf1[INET6_ADDRSTRLEN];

	if (mma->state == newstate)
		return;

	debug_log(3, "Managed address %s changed state %s -> %s.\n",
		  format_addr(buf1, &mma->base->parent->address),
		  _mgaddr_stname[mma->state], _mgaddr_stname[newstate]);

	if (mma->state >= MBLTY_MMA_STATE_INS_LINK_ROUTE &&
	    newstate < MBLTY_MMA_STATE_INS_LINK_ROUTE)
		mblty_delete_policy(&mma->linkroute);

	mma->state = newstate;

	if (newstate == MBLTY_MMA_STATE_READY) {
		mblty_managed_interest_t *i;
		/* available must not remove mma */
		list_for_each_entry (i, &mma->interest, entry) {
			if (i->ops && i->ops->available)
				i->ops->available(i);
		}
	}
}

static void
mma_install_link_route(mblty_managed_addr_t *mma)
{
	mma_change_state(mma, MBLTY_MMA_STATE_INS_LINK_ROUTE);
	mblty_add_policy(&mma->linkroute);
}

mblty_managed_addr_t *
mblty_managed_addr_obtain(mblty_interface_t *intf, mblty_prefix_t *prefix,
			  struct in6_addr *addr)
{
	mblty_base_address_t *base;
	mblty_managed_addr_t *mma;

	list_for_each_entry (mma, &intf->managed, entry) {
		if (in6_addr_compare(&mma->base->parent->address, addr) == 0) {
			if (mma->prefix && mma->prefix != prefix)
				return NULL;
			else if (prefix && mma->prefix == NULL) {
				mma_prepare_prefix(mma, prefix);
				if (mma->state == MBLTY_MMA_STATE_READY)
					mma_install_link_route(mma);
			}
			return mma;
		}
	}

	mma = allocate_object(mblty_managed_addr_t);
	if (mma == NULL)
		return NULL;

	base = mblty_obtain_address(intf, addr);
	if (base == NULL) {
		free_object(mma);
		return NULL;
	}

	mblty_managed_addr_init(mma, base, prefix);
	mblty_drop_address(base);

	return mma;
}

static void
mma_install(mblty_managed_addr_t *mma, unsigned newstate)
{
	mma_change_state(mma, newstate);

	mblty_intf_addr_change_to(&mma->inst,
				  MBLTY_INTF_ADDR_STATE_TENTATIVE);
}

void
mblty_managed_addr_link(mblty_managed_addr_t *mma, mblty_managed_interest_t *i)
{
	int install = (list_empty(&mma->interest));

	list_add_tail(&i->entry, &mma->interest);

	if (install) {
		mma_install(mma, MBLTY_MMA_STATE_INSTALLING);
	} else if (i->ops) {
		if (mma->state == MBLTY_MMA_STATE_READY) {
			if (i->ops->available)
				i->ops->available(i);
		} else if (mma->state == MBLTY_MMA_STATE_DAD_FAILED) {
			if (i->ops->failed)
				i->ops->failed(i);
		}
	}
}

static void
mblty_managed_addr_deinit(mblty_managed_addr_t *mma)
{
	if (mma->prefix) {
		mblty_delete_policy(&mma->linkroute);
		mblty_put_prefix(mma->prefix);
		mma->prefix = NULL;
	}

	list_del(&mma->entry);
	ndisc_addr_unregister(&mma->nar);
	mblty_intf_addr_remove(&mma->inst);
	mblty_drop_address(mma->base);
}

static int
mma_check_aliveness(mblty_managed_addr_t *mma)
{
	if (mma->flags & MBLTY_MMA_F_ALIVE)
		return 0;

	if (list_empty(&mma->interest)) {
		mblty_managed_addr_deinit(mma);
		free_object(mma);
		return -1;
	}

	return 0;
}

void
mblty_managed_addr_unlink(mblty_managed_addr_t *mma,
			  mblty_managed_interest_t *i)
{
	list_del(&i->entry);
	mma_check_aliveness(mma);
}

static void
mma_finished_dad(mblty_managed_addr_t *mma)
{
	debug_assert(mma->state < MBLTY_MMA_STATE_CLAIMED,
		     "address was already claimed");

	mma_change_state(mma, MBLTY_MMA_STATE_CLAIMED);

	mblty_intf_addr_change_to(&mma->inst,
				  MBLTY_INTF_ADDR_STATE_READY);
}

static void
mma_claimed(ndisc_address_record_t *rec)
{
	mma_finished_dad(container_of(rec, mblty_managed_addr_t, nar));
}

static void
mma_dad_failed(ndisc_address_record_t *rec)
{
	mblty_managed_addr_t *mma =
		container_of(rec, mblty_managed_addr_t, nar);
	mblty_managed_interest_t *i, *tmp;

	mma_change_state(mma, MBLTY_MMA_STATE_DAD_FAILED);
	mblty_intf_addr_change_to(&mma->inst, MBLTY_INTF_ADDR_STATE_NOINFO);

	mma->flags |= MBLTY_MMA_F_ALIVE;
	list_for_each_entry_safe (i, tmp, &mma->interest, entry) {
		if (i->ops && i->ops->failed)
			i->ops->failed(i);
	}
	mma->flags &= ~MBLTY_MMA_F_ALIVE;
	mma_check_aliveness(mma);
}

static void
mma_policy_added(mblty_policy_t *pol, int res)
{
	mblty_managed_addr_t *mma =
		container_of(pol, mblty_managed_addr_t, linkroute);

	mma_change_state(mma, MBLTY_MMA_STATE_READY);
}

void
mblty_managed_addr_proceed(mblty_managed_addr_t *mma)
{
	if (mma->flags & MBLTY_MMA_F_RUNNING)
		return;

	mma->flags |= MBLTY_MMA_F_RUNNING;

	mma_change_state(mma, MBLTY_MMA_STATE_CLAIMING);
	ndisc_addr_proceed(&mma->nar);
}

static void
mma_ia_changed_state(mblty_intf_addr_t *intfaddr, mblty_intf_addr_state_t old)
{
	mblty_managed_addr_t *mma =
		container_of(intfaddr, mblty_managed_addr_t, inst);

	if (mma->state == MBLTY_MMA_STATE_INSTALLING ||
	    mma->state == MBLTY_MMA_STATE_RECHECKING) {
		if (mblty_interface_has_link(mma->base->intf))
			mblty_managed_addr_proceed(mma);
	} else if (mma->state == MBLTY_MMA_STATE_CLAIMED) {
		if (mma->prefix) {
			mma_install_link_route(mma);
		} else {
			mma_change_state(mma, MBLTY_MMA_STATE_READY);
		}
	}
}

void
mblty_managed_addr_recheck(mblty_managed_addr_t *mma)
{
	if (!(mma->flags & MBLTY_MMA_F_RUNNING))
		return;

	mma->flags &= ~MBLTY_MMA_F_HADCLAIMED;
	mma->flags &= ~MBLTY_MMA_F_RUNNING;

	if (mma->state == MBLTY_MMA_STATE_DAD_FAILED) {
		mma_install(mma, MBLTY_MMA_STATE_INSTALLING);
		return;
	} else if (mma->state >= MBLTY_MMA_STATE_CLAIMED) {
		mma->flags |= MBLTY_MMA_F_HADCLAIMED;
	}

	ndisc_addr_reset(&mma->nar);

	if (mma->state == MBLTY_MMA_STATE_READY) {
		mblty_managed_interest_t *i, *tmp;
		mma->flags |= MBLTY_MMA_F_ALIVE;
		list_for_each_entry_safe (i, tmp, &mma->interest, entry) {
			if (i->ops && i->ops->lost)
				i->ops->lost(i, 1);
		}
		mma->flags &= ~MBLTY_MMA_F_ALIVE;
		if (mma_check_aliveness(mma) < 0)
			return;
	}

	mma_install(mma, MBLTY_MMA_STATE_RECHECKING);
}

int
mblty_is_addr_available(mblty_managed_addr_t *mma)
{
	if (mma == NULL)
		return 0;
	return mma->state == MBLTY_MMA_STATE_READY;
}

static void
linklocal_available(mblty_managed_interest_t *inter)
{
	mblty_link_local_t *ll =
		container_of(inter, mblty_link_local_t, mginter);

	mblty_link_linklocal(ll);
}

static void
linklocal_lost(mblty_managed_interest_t *inter, int will)
{
	mblty_link_local_t *ll =
		container_of(inter, mblty_link_local_t, mginter);

	if (will)
		mblty_unlink_linklocal(ll);
	else
		mblty_remove_linklocal(ll);
}

static void
linklocal_failed(mblty_managed_interest_t *inter)
{
	mblty_link_local_t *ll =
		container_of(inter, mblty_link_local_t, mginter);

	mblty_remove_linklocal(ll);
}

mblty_network_address_t *
mblty_prefix_get_address(mblty_router_prefix_t *pfx, struct in6_addr *addr)
{
	mblty_network_address_t *netaddr;

	list_for_each_entry (netaddr, &pfx->addresses, entry) {
		if (in6_addr_compare(addr, mblty_get_addr(netaddr)) == 0)
			return netaddr;
	}

	return NULL;
}

