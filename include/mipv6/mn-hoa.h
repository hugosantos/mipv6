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

#ifndef _MIPV6_PRIV_MN_HOA_H_
#define _MIPV6_PRIV_MN_HOA_H_

#include <mblty/tunnel.h>
#include <mblty/router.h>
#include <mblty/list-support.h>
#include <mblty/heap-support.h>

#include <mipv6/protocol.h>
#include <mipv6/proto-sec.h>

typedef struct mipv6_mn_ha mipv6_mn_ha_t;
typedef struct mipv6_mn_hoa mipv6_mn_hoa_t;
typedef struct mipv6_mn_ha_router mipv6_mn_ha_router_t;
typedef struct mipv6_mn_individual mipv6_mn_individual_t;

struct mipv6_mn_ha {
	struct in6_addr address;

	struct list_entry instances;

#define MIPV6_MN_HA_HAS_DEF_EUI64	0x0001
	uint32_t flags;

	mblty_eui64_t def_eui64;

	int refcount;
	struct list_entry entry;
};

struct mipv6_mn_ha_router {
	struct mblty_router r;

	struct mipv6_mn_ha *common;

	struct mblty_interface *tun_intf;
	struct mblty_tunnel *tunnel;

	struct list_entry instance;
};

struct mipv6_tunnel;
struct mipv6_mn_hoa;

struct mipv6_mn_binding_ops {
	/* called before the update to the binding context
	 * (and sending of Binding Update, etc) with the
	 * selected Care-of address */
	void (*pre_update)(mipv6_mn_hoa_t *, mblty_network_address_t *);
	/* called after the binding context update is
	 * acknowledged. If no ack is expected, this callback
	 * is triggered after the binding context updates it's
	 * internal state */
	void (*post_update)(mipv6_mn_hoa_t *);
	void (*invalidate_addr)(mipv6_mn_hoa_t *, mblty_network_address_t *);
	void (*clear_state)(mipv6_mn_hoa_t *);
};

typedef enum {
	MIPV6_MN_LOC_LIMBO	= 0,
	MIPV6_MN_LOC_HOME	= 1,
	MIPV6_MN_LOC_FOREIGN	= 2,
} mipv6_location_t;

struct mipv6_mn_hoa {
	struct mblty_network_address a;

	mblty_intf_addr_t inst;

	struct mipv6_binding_context binding_ctx;

	mipv6_location_t location;

#define MIPV6_MN_HOA_NO_RO		0x0001
#define MIPV6_MN_HOA_PROTECTED		0x0002
	uint32_t flags;

	/* list of addresses in the predecent level that
	 * are available for this higher-level address to
	 * use, ordered by preference */
	struct heap lower_list;

	/* list of individual remote binding contexts
	 * associated with this HoA */
	struct list_entry individual_ctxs;

	mblty_network_address_t *active_coa;
	mblty_policy_t defroute;
	ndisc_address_record_t nar;

	struct mipv6_mn_binding_ops *ops;

	int (*compare_coa_pol)(struct mipv6_mn_hoa *,
			       struct mblty_network_address *,
			       struct mblty_network_address *);

	struct list_entry entry;
};

struct mipv6_mn_individual;

struct mipv6_mn_individual_ops {
	/* called when the parent hoa's attachment address
	 * changes and the individual needs to be updated.
	 * Before being called the context enters the PREPARING
	 * state, which then switches to READY after
	 * mipv6_mn_individual_done_preparing is called. prepare()
	 * may be triggered while a previous preparation is in
	 * course, in that case, the state related to the previous
	 * should be cleaned up and a new preparation be started. */
	void (*prepare)(struct mipv6_mn_individual *);
	/* triggered when the binding context associated with the
	 * individual context is acknowledged. Note that if no
	 * Binding Ack is requested this will be exactly after the
	 * Binding Update is successfully sent */
	void (*completed_reg)(struct mipv6_mn_individual *);
	/* called when the expire timer expires before the
	 * individual context is removed */
	void (*expired)(struct mipv6_mn_individual *);
	/* called when the individual context is being destroyed.
	 * any extra-state or preparation procedures should be
	 * removed/canceled here as well as the individual
	 * context instance */
	void (*destructor)(struct mipv6_mn_individual *);
};

struct mipv6_mn_individual {
	struct mipv6_mn_hoa *parent;

	struct in6_addr remote;

	struct mipv6_binding_context binding_ctx;

#define MIPV6_MN_IND_LOCKED		0x01
#define MIPV6_MN_IND_PREPARING		0x02
#define MIPV6_MN_IND_PERMANENT		0x04
#define MIPV6_MN_IND_AUTHERR		0x08
#define MIPV6_MN_IND_NEEDS_UPDATE	0x10
	uint32_t flags;

	struct mipv6_mn_individual_ops *ops;

	uint64_t last_required;

	uint64_t st_last_update;
	uint32_t st_last_value;

	struct list_entry entry;
};

static inline struct mipv6_mn_ha_router *
mipv6_get_hoa_ha_router(struct mipv6_mn_hoa *hoa)
{
	return container_of(mblty_addr_router(&hoa->a),
			    struct mipv6_mn_ha_router, r);
}

static inline struct mipv6_mn_ha *
mipv6_get_hoa_ha(struct mipv6_mn_hoa *hoa)
{
	struct mipv6_mn_ha_router *r = mipv6_get_hoa_ha_router(hoa);
	return r ? r->common : NULL;
}

static inline struct mblty_network_address *
mipv6_mn_hoa_active_coa(struct mipv6_mn_hoa *hoa)
{
	return hoa->active_coa;
}

void mipv6_mn_state_init();
void mipv6_mn_state_shutdown();

struct mipv6_mn_hoa *mipv6_mn_alloc_hoa(struct mblty_router_prefix *,
					struct in6_addr *);
struct mipv6_mn_hoa *mipv6_mn_check_alloc_hoa(struct mblty_router_prefix *,
					      struct in6_addr *);
struct mipv6_mn_hoa *mipv6_mn_get_hoa(struct in6_addr *);

void mipv6_mn_tentative_hoa(struct in6_prefix *, struct in6_addr *);
void mipv6_mn_allocate_hoa(struct in6_addr *, struct in6_prefix *,
			   struct in6_addr *, int fact);

void mipv6_mn_foreach_hoa(int (*)(struct mipv6_mn_hoa *, void *), void *);
void mipv6_mn_foreach_hoa_individual(struct mipv6_mn_hoa *,
				     int (*)(struct mipv6_mn_individual *,
				     void *), void *);

int mipv6_is_ha_router(struct mblty_router *rt);

void mipv6_mn_hoa_add_ha(struct mipv6_mn_hoa *, struct mipv6_mn_ha *);
mipv6_mn_ha_t *mipv6_get_home_agent(struct in6_addr *);

void mipv6_mn_distribute_address(struct mblty_network_address *);
void mipv6_mn_lost_address(struct mblty_network_address *);

mblty_network_address_t *mipv6_mn_hoa_top_coa(struct mipv6_mn_hoa *);

int mipv6_mn_hoa_set_nai(struct mipv6_mn_hoa *, const char *);
void mipv6_mn_hoa_set_ipsec_auth(struct mipv6_mn_hoa *, int val);

struct mipv6_mn_individual *
mipv6_mn_hoa_alloc_individual(struct mipv6_mn_hoa *, struct in6_addr *);
struct mipv6_mn_individual *
mipv6_mn_hoa_get_individual(struct mipv6_mn_hoa *, struct in6_addr *);
void mipv6_mn_unlock_individual(struct mipv6_mn_individual *);
void mipv6_mn_individual_update(struct mipv6_mn_individual *);
void mipv6_mn_individual_done_preparing(struct mipv6_mn_individual *);

void mipv6_mn_individual_is_required(struct mipv6_mn_individual *);

void mipv6_mn_trigger_ro(struct in6_addr *, struct in6_addr *);
void mipv6_mn_stop_ro(struct in6_addr *, struct in6_addr *);

#endif /* _MIPV6_PRIV_MN_HOA_H_ */
