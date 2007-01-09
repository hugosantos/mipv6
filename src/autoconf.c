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
#include <mblty/autoconf.h>
#include <mblty/interface.h>
#include <mblty/base-support.h>

#ifndef ND_OPT_PI_FLAG_RADDR
#define ND_OPT_PI_FLAG_RADDR	0x20
#endif

#ifndef ND_OPT_RTR_ADV_INTERVAL
#define ND_OPT_RTR_ADV_INTERVAL	7

struct nd_opt_adv_interval {
	uint8_t	 nd_opt_adv_interval_type;
	uint8_t  nd_opt_adv_interval_len;
	uint16_t nd_opt_adv_interval_reserved;
	uint32_t nd_opt_adv_interval_ival;
};
#endif

#ifndef ND_RA_FLAG_HOME_AGENT
#define ND_RA_FLAG_HOME_AGENT	8

struct nd_opt_home_agent_info {
	uint8_t  nd_opt_home_agent_info_type;
	uint8_t  nd_opt_home_agent_info_len;
	uint16_t nd_opt_home_agent_info_reserved;
	int16_t  nd_opt_home_agent_info_preference;
	uint16_t nd_opt_home_agent_info_lifetime;
};
#endif

static void autoconf_def_intf_event(mblty_interface_t *,
				    mblty_intf_event_t ev);

static struct mblty_autoconf_strategy _def_strategy = {
	.intf_event = autoconf_def_intf_event,
	.handle_ra = mblty_std_handle_ra,
};

static void mblty_handle_all_RAs(ndisc_handler_context_t *);

static ndisc_handler_t autoconf_rtadv_handler = {
	.event = mblty_handle_all_RAs,
};

static mblty_router_ops_t autoconf_router_ops = {
	.link_down = mblty_remove_router,
};

static void unicast_removing_addr(mblty_network_address_t *);
static void unicast_router_reachable(mblty_network_address_t *);
static void unicast_router_unreachable(mblty_network_address_t *);
static void unicast_addr_available(mblty_managed_interest_t *);
static void unicast_addr_lost(mblty_managed_interest_t *, int will);
static void unicast_addr_failed(mblty_managed_interest_t *);

static int uni_preference(mblty_network_address_t *);
static void defroute_pol_added(mblty_policy_t *, int res);

static mblty_addr_category_t unicast_category = {
	.name = "unicast",
	.preference = uni_preference,
};

static mblty_network_address_ops_t unicast_ops = {
	.removing = unicast_removing_addr,
	.reachable = unicast_router_reachable,
	.unreachable = unicast_router_unreachable,
};

static mblty_managed_interest_ops_t unicast_interest_ops = {
	.available = unicast_addr_available,
	.lost = unicast_addr_lost,
	.failed = unicast_addr_failed,
};

static mblty_policy_ops_t defroute_pol_ops = {
	.added = defroute_pol_added,
};

static struct in6_prefix default_route = {
	.address = IN6ADDR_ANY_INIT,
	.prefixlen = 0,
};

static const char *_uni_stname[] = {
	"NoInfo",
	"Installing default route",
	"Capable of global routing",
};

static void
autogen_address(struct in6_addr *target, struct in6_prefix *pfx,
		mblty_eui64_t *eui64)
{
	in6_addr_copy(target, &pfx->address);
	memcpy(target->s6_addr + 8, eui64->data, 8);
}

static void
generate_unicast(mblty_router_prefix_t *netpfx, struct in6_addr *addr)
{
	mblty_unicast_address_t *uni;
	mblty_autoconf_data_t *data;

	data = mblty_rtr_intf(netpfx->owner)->autoconf_data;

	uni = allocate_object(mblty_unicast_address_t);
	if (uni == NULL)
		return;

	uni->preference = 0;
	uni->state = MBLTY_UNI_STATE_NOINFO;
	uni->flags = 0;
	uni->mgaddr = NULL;

	if (mblty_init_address(&uni->base, addr, &unicast_category,
			       netpfx, &unicast_ops) < 0) {
		free_object(uni);
		return;
	}

	uni->mgaddr = mblty_managed_addr_obtain(mblty_pfx_intf(netpfx),
						netpfx->parent->parent, addr);
	if (uni->mgaddr == NULL) {
		mblty_deinit_address(&uni->base);
		free_object(uni);
		return;
	}

	/* default route */
	mblty_init_policy(&uni->defroute);
	mblty_fill_policy(&uni->defroute, &default_route, &uni->base);
	uni->defroute.ops = &defroute_pol_ops;

	uni->mginter.ops = &unicast_interest_ops;

	/* starts the claiming process */
	mblty_managed_addr_link(uni->mgaddr, &uni->mginter);
}

static void
generate_addresses(mblty_router_prefix_t *netpfx)
{
	struct in6_addr fulladdr;

	if (netpfx->flags & MBLTY_NETPFX_NO_AUTOCONF)
		return;

	if (!(mblty_pfx_intf(netpfx)->flags & MBLTY_INTF_HAS_EUI64)) {
		debug_log(3, "Interface %s has no EUI64, won't generate "
			  "address.\n", mblty_pfx_intf(netpfx)->osh->name);
		return;
	}

	if (mblty_get_rtr_pfx(netpfx)->prefixlen != 64) {
		debug_log(3, "Prefix length is not 64, skipping autoconf.\n");
		return;
	}

	autogen_address(&fulladdr, mblty_get_rtr_pfx(netpfx),
			&mblty_pfx_intf(netpfx)->eui64);

	generate_unicast(netpfx, &fulladdr);
}

static mblty_router_prefix_t *
update_router_prefix(struct mblty_router *rtr, struct in6_prefix *pfx,
		     struct nd_opt_prefix_info *pi, uint32_t flags)
{
	struct mblty_autoconf_data *data = mblty_rtr_intf(rtr)->autoconf_data;
	struct mblty_router_prefix *netpfx;
	struct in6_prefix tmp;

	in6_prefix_copy_applied(&tmp, pfx);

	netpfx = mblty_router_get_prefix(rtr, &tmp);
	if (netpfx == NULL) {
		if (pi->nd_opt_pi_valid_time == 0)
			return NULL;

		netpfx = mblty_router_announced_prefix(rtr, &tmp, flags);
		if (netpfx == NULL)
			return NULL;

		if (data->flags & MBLTY_AUTOCONF_F_GENERATED)
			generate_addresses(netpfx);
	}

	mblty_prefix_update_lifetimes(netpfx, ntohl(pi->nd_opt_pi_valid_time),
				      ntohl(pi->nd_opt_pi_preferred_time));

	return netpfx;
}

static void
ra_handle_pfx_info(mblty_router_t *rtr, struct nd_opt_prefix_info *pfx_info)
{
	struct mblty_autoconf_data *data = mblty_rtr_intf(rtr)->autoconf_data;
	struct in6_prefix pfx;
	uint32_t flags = 0;

	if (!(pfx_info->nd_opt_pi_flags_reserved & ND_OPT_PI_FLAG_AUTO))
		return;

	in6_addr_copy(&pfx.address, &pfx_info->nd_opt_pi_prefix);

	if (IN6_IS_ADDR_LINKLOCAL(&pfx.address))
		return;

	if (pfx_info->nd_opt_pi_flags_reserved & ND_OPT_PI_FLAG_ONLINK)
		flags |= MBLTY_NETPFX_ONLINK;

	pfx.prefixlen = pfx_info->nd_opt_pi_prefix_len;

	if (data->flags & MBLTY_AUTOCONF_F_PREFIX)
		update_router_prefix(rtr, &pfx, pfx_info, flags);

	if (pfx_info->nd_opt_pi_flags_reserved & ND_OPT_PI_FLAG_RADDR) {
		mblty_interface_t *intf = mblty_rtr_intf(rtr);
		mblty_router_t *old;

		/* Radvd <= 0.9.1 advertises the prefix as the router's assigned
		 * address. This does not allow us to distinguish routers in site-
		 * multihoming scenarios, so we ignore these R-bits */
		if (pfx.address.s6_addr[8] == 0 && pfx.address.s6_addr[9] == 0 &&
		    pfx.address.s6_addr[10] == 0 && pfx.address.s6_addr[11] == 0 &&
		    pfx.address.s6_addr[12] == 0 && pfx.address.s6_addr[13] == 0 &&
		    pfx.address.s6_addr[14] == 0 && pfx.address.s6_addr[15] == 0)
			return;

		/* we only do R-bit processing after adding the prefix
		 * to make sure the address-using modules have a new address
		 * to use in case an alias colision is detected an the
		 * previous router is removed. */
		old = mblty_intf_get_router(intf, &pfx.address);

		if (old && old == rtr)
			return;

		if (old && old != rtr) {
			debug_log(2, "Globally addressed router address "
				  "collision. Moved links? Removing old.\n");
			mblty_remove_router(old);
		}

		mblty_add_router_alias(rtr, &pfx.address);
	}
}

static void
ra_handle_adv_int(mblty_router_t *rtr, struct nd_opt_adv_interval *advint,
		  uint32_t *lifetime)
{
	uint32_t value = ntohl(advint->nd_opt_adv_interval_ival);

	/* XXX this robustness variable should be configurable
	 *
	 *     we assume that two missed RAs are enough to
	 *     decide the router is no longer available */

	if ((value * 2) < *lifetime) {
		mblty_update_router_lifetime(rtr, value * 2);
		*lifetime = (value * 2);
	}
}

void
mblty_std_handle_ra(struct mblty_interface *intf, ndisc_handler_context_t *ctx)
{
	struct mblty_autoconf_data *data = intf->autoconf_data;
	struct nd_router_advert *ra = ctx->hdr.rtadv;
	uint32_t router_lifetime, rtrflags;
	struct mblty_router *rtr;
	int llcount = 0;

	rtr = mblty_intf_get_router(intf, ctx->source);

	router_lifetime = (uint32_t)ntohs(ra->nd_ra_router_lifetime) * 1000;
	if (router_lifetime == 0) {
		if (rtr)
			mblty_remove_router(rtr);

		return;
	}

	if (rtr == NULL) {
		/* need to allocate a new router instance */
		rtr = mblty_alloc_router(intf, ctx->source, &autoconf_router_ops);
		if (rtr == NULL)
			return;

		if (data->flags & MBLTY_AUTOCONF_F_REACH) {
			struct in6_addr *address = mblty_rtr_address(rtr);

			/* default autoconf strategy, default reachability */
			rtr->reach = mblty_alloc_standard_reach(intf->osh,
								address, 1, 0);
			debug_assert(rtr->reach, "Failed to allocate router "
						 "reachability strategy.");

			mblty_setup_router_reachability(rtr);
		}
	}

	rtrflags = rtr->flags;

	if (ctx->hdr.rtadv->nd_ra_flags_reserved & ND_RA_FLAG_MANAGED)
		rtr->flags |= MBLTY_ROUTER_MANAGED;
	else
		rtr->flags &= ~MBLTY_ROUTER_MANAGED;

	if (ctx->hdr.rtadv->nd_ra_flags_reserved & ND_RA_FLAG_HOME_AGENT)
		rtr->flags |= MBLTY_ROUTER_HOME_AGENT;
	else
		rtr->flags &= ~MBLTY_ROUTER_HOME_AGENT;

	if (rtrflags != rtr->flags)
		mblty_router_flags_changed(rtr, rtrflags);

	/* update this router's lifetime as a default router */
	mblty_update_router_lifetime(rtr, router_lifetime);

	while (ndisc_handctx_next_opt(ctx)) {
		if (ctx->opt.hdr == NULL)
			break;

		if (ctx->opt.hdr->nd_opt_type == ND_OPT_PREFIX_INFORMATION) {
			ra_handle_pfx_info(rtr, ctx->opt.pi);
		} else if (ctx->opt.hdr->nd_opt_type == ND_OPT_RTR_ADV_INTERVAL) {
			ra_handle_adv_int(rtr, ctx->opt.advint,
					  &router_lifetime);
		} else if (ctx->opt.hdr->nd_opt_type == ND_OPT_SOURCE_LINKADDR) {
			if (llcount) {
				debug_log(3, "Received duplicate "
					     "ND_OPT_SOURCE_LINKADDR, ignoring.\n");
			} else {
				uint8_t *addr = ctx->opt.raw + 2;
				int len = ctx->opt.hdr->nd_opt_len * 8 - 2;

				mblty_router_set_link_addr(rtr, addr, len);

				llcount++;
			}
		}
	}
}

void
mblty_do_std_router_solicit(struct mblty_interface *intf, struct in6_addr *src)
{
	struct in6_addr to, from;
	struct {
		struct nd_router_solicit h;
		uint8_t opt[MBLTY_NEIGH_LLADDR_OPT_MAXSIZE];
	} rs;
	int rs_len = 0;

	memset(&to, 0, sizeof(to));
	memset(&from, 0, sizeof(from));

	/* all ipv6 nodes address */
	to.s6_addr[ 0] = 0xff;
	to.s6_addr[ 1] = 0x02;
	to.s6_addr[15] = 0x02;

	if (src == NULL) {
		if (mblty_linklocal_for(intf, &to, &from) < 0) {
			debug_log(2, "Failed to send RtSol.\n");
			return;
		}
	} else {
		in6_addr_copy(&from, src);
	}

	if (!IN6_IS_ADDR_UNSPECIFIED(&from)) {
		rs_len = ndisc_prepare_lladdr_opt(ND_OPT_SOURCE_LINKADDR,
						  rs.opt, sizeof(rs.opt),
						  intf->osh);
	}

	if (rs_len < 0)
		return;

	memset(&rs, 0, sizeof(rs));
	rs.h.nd_rs_type = ND_ROUTER_SOLICIT;
	rs.h.nd_rs_code = 0;

	rs_len += sizeof(struct nd_router_solicit);

	debug_log(2, "Sending Router Solicitation in %s.\n", intf->osh->name);

	icmpv6_send(&to, &from, intf->osh, 255, &rs.h.nd_rs_hdr, rs_len);
}

static void
in6addr_all_nodes_init(struct in6_addr *addr)
{
	memset(addr, 0, sizeof(struct in6_addr));
	addr->s6_addr[ 0] = 0xff;
	addr->s6_addr[ 1] = 0x02;
	addr->s6_addr[15] = 0x01;
}

static void
autoconf_def_prepare(mblty_interface_t *intf)
{
	struct in6_addr linklocal;
	struct in6_prefix pfx;

	memset(&pfx, 0, sizeof(pfx));
	pfx.prefixlen = 64;
	pfx.address.s6_addr[0] = 0xfe;
	pfx.address.s6_addr[1] = 0x80;

	if (!(intf->flags & MBLTY_INTF_HAS_EUI64))
		return;

	autogen_address(&linklocal, &pfx, &intf->eui64);
	mblty_allocate_linklocal(intf, &linklocal, 1);
}

static void
autoconf_join_all_nodes(mblty_interface_t *intf)
{
	struct in6_addr in6addr_all_nodes;

	/* listen to RAs */
	in6addr_all_nodes_init(&in6addr_all_nodes);
	icmpv6_join_mc(intf->osh, &in6addr_all_nodes);
}

static void
autoconf_leave_all_nodes(mblty_interface_t *intf)
{
	struct in6_addr in6addr_all_nodes;

	in6addr_all_nodes_init(&in6addr_all_nodes);
	icmpv6_leave_mc(intf->osh, &in6addr_all_nodes);
}

static void
autoconf_def_cleanup(struct mblty_interface *intf)
{
}

static void
autoconf_def_intf_event(mblty_interface_t *intf, mblty_intf_event_t ev)
{
	mblty_autoconf_data_t *data = intf->autoconf_data;
	struct in6_addr any = in6addr_any;

	switch (ev) {
	case MBLTY_INTF_EV_UP:
		if (data->flags & MBLTY_AUTOCONF_F_MANAGED) {
			/* going up, we handle all the addresses */
			debug_assert(mblty_os_intf_disable(intf->osh,
					MBLTY_OS_INTF_CAP_AUTOCONF) == 0,
				     "Disabling of kernel autoconf. failed.");

			mblty_os_intf_remove_kernel_addresses(intf->osh);
			mblty_os_intf_remove_kernel_routes(intf->osh);

			autoconf_def_prepare(intf);
		}

		autoconf_join_all_nodes(intf);
		break;

	case MBLTY_INTF_EV_DOWN:
		autoconf_leave_all_nodes(intf);

		if (data->flags & MBLTY_AUTOCONF_F_MANAGED)
			autoconf_def_cleanup(intf);
		break;

	case MBLTY_INTF_EV_LINK_UP:
		/* XXX
		 * Before a host sends an initial solicitation, it SHOULD delay
		 * the transmission for a random amount of time between 0 and
		 * MAX_RTR_SOLICITATION_DELAY.  This serves to alleviate
		 * congestion when many hosts start up on a link at the same
		 * time, such as might happen after recovery from a power
		 * failure.  If a host has already performed a random delay
		 * since the interface became (re)enabled (e.g., as part of
		 * Duplicate Address Detection [ADDRCONF]) there is no need to
		 * delay again before sending the first Router Solicitation
		 * message.
		 *
		 * MAX_RTR_SOLICITATION_DELAY = 1 second
		 */

		if (data->flags & MBLTY_AUTOCONF_F_MANAGED) {
			if (data->flags & MBLTY_AUTOCONF_PF_EARLY_RS)
				mblty_do_std_router_solicit(intf, &any);
		}
		break;

	case MBLTY_INTF_EV_LINK_DOWN:
		break;

	case MBLTY_INTF_EV_REMOVING:
		free_object(intf->autoconf_data);
		break;

	case MBLTY_INTF_EV_LL_AVAIL:
		if (data->flags & MBLTY_AUTOCONF_F_MANAGED) {
			if (!(data->flags & MBLTY_AUTOCONF_PF_EARLY_RS))
				mblty_do_std_router_solicit(intf, NULL);
		}
		break;

	case MBLTY_INTF_EV_LL_LOST:
		break;

	default:
		break;
	}
}

static inline mblty_unicast_address_t *
uni_from(mblty_network_address_t *addr)
{
	return container_of(addr, mblty_unicast_address_t, base);
}

static void
unicast_addr_change_state(mblty_unicast_address_t *uni, unsigned state)
{
	char buf1[INET6_ADDRSTRLEN];

	if (uni->state == state)
		return;

	debug_log(3, "Unicast address %s changed state, %s -> %s.\n",
		  format_addr(buf1, mblty_get_addr(&uni->base)),
		  _uni_stname[uni->state], _uni_stname[state]);

	if (uni->state == MBLTY_UNI_STATE_FULL_REACH)
		mblty_using_router(mblty_addr_router(&uni->base), -1);
	else if (state == MBLTY_UNI_STATE_FULL_REACH)
		mblty_using_router(mblty_addr_router(&uni->base), +1);

	if (uni->state == MBLTY_UNI_STATE_FULL_REACH)
		mblty_address_lost(&uni->base);
	else if (state == MBLTY_UNI_STATE_FULL_REACH)
		mblty_address_available(&uni->base);

	uni->state = state;
}

static void
uni_proceed_for_full(mblty_unicast_address_t *uni)
{
	if (uni->flags & MBLTY_UNI_F_RTREACHABLE) {
		unicast_addr_change_state(uni, MBLTY_UNI_STATE_INS_DEF_ROUTE);
		mblty_add_policy(&uni->defroute);
	}
}

static void
defroute_pol_added(mblty_policy_t *pol, int res)
{
	mblty_unicast_address_t *uni =
		container_of(pol, mblty_unicast_address_t, defroute);

	unicast_addr_change_state(uni, MBLTY_UNI_STATE_FULL_REACH);
}

static void
unicast_addr_reset(mblty_unicast_address_t *uni)
{
	if (uni->state >= MBLTY_UNI_STATE_INS_DEF_ROUTE)
		mblty_delete_policy(&uni->defroute);

	unicast_addr_change_state(uni, MBLTY_UNI_STATE_NOINFO);
}

static void
unicast_removing_addr(mblty_network_address_t *addr)
{
	mblty_unicast_address_t *uni = uni_from(addr);
	char buf[INET6_ADDRSTRLEN];

	debug_log(1, "Removing Unicast address %s\n", format_addr(buf,
		  mblty_get_addr(addr)));

	unicast_addr_reset(uni);
	mblty_managed_addr_unlink(uni->mgaddr, &uni->mginter);
	uni->mgaddr = NULL;
}


static void
unicast_router_reachable(mblty_network_address_t *addr)
{
	mblty_unicast_address_t *uni = uni_from(addr);
	char buf1[INET6_ADDRSTRLEN];

	if (uni->flags & MBLTY_UNI_F_RTREACHABLE)
		return;

	uni->flags |= MBLTY_UNI_F_RTREACHABLE;

	debug_log(5, "Marking unicast address %s as globally routable.\n",
		  format_addr(buf1, mblty_get_addr(addr)));

	/* router is reachable again, we'll install the
	 * default route and subsequently trigger the
	 * availability of this address */

	if (uni->state == MBLTY_UNI_STATE_NOINFO &&
	    mblty_is_addr_available(uni->mgaddr))
		uni_proceed_for_full(uni);
}

static void
unicast_router_unreachable(mblty_network_address_t *addr)
{
	mblty_unicast_address_t *uni = uni_from(addr);
	char buf1[INET6_ADDRSTRLEN];

	/* if router isn't available, we'll remove the default
	 * route if we had one. this address might also no longer
	 * be usable, so we'll trigger it's loss. */

	if (!(uni->flags & MBLTY_UNI_F_RTREACHABLE))
		return;

	uni->flags &= ~MBLTY_UNI_F_RTREACHABLE;

	debug_log(5, "Unicast address %s is no longer globally routable.\n",
		  format_addr(buf1, mblty_get_addr(addr)));

	if (uni->state > MBLTY_UNI_STATE_NOINFO) {
		unicast_addr_change_state(uni, MBLTY_UNI_STATE_NOINFO);
		mblty_delete_policy(&uni->defroute);
	}
}

static void
unicast_addr_available(mblty_managed_interest_t *inter)
{
	mblty_unicast_address_t *uni =
		container_of(inter, mblty_unicast_address_t, mginter);

	unicast_addr_change_state(uni, MBLTY_UNI_STATE_INS_DEF_ROUTE);
	mblty_add_policy(&uni->defroute);
}

static void
unicast_addr_lost(mblty_managed_interest_t *inter, int willrecheck)
{
	mblty_unicast_address_t *uni
		= container_of(inter, mblty_unicast_address_t, mginter);

	unicast_addr_reset(uni);
}

static void
unicast_addr_failed(mblty_managed_interest_t *inter)
{
	unicast_addr_lost(inter, 0);
}

static int
uni_preference(mblty_network_address_t *addr)
{
	return uni_from(addr)->preference;
}

static void
mblty_handle_all_RAs(ndisc_handler_context_t *ctx)
{
	mblty_interface_t *intf = mblty_get_interface(ctx->iif);

	if (intf == NULL)
		return;

	if (intf->autoconf && intf->autoconf->handle_ra)
		intf->autoconf->handle_ra(intf, ctx);

	mblty_put_interface(intf);
}

static void mblty_autoconf_shutdown();
static struct mblty_shutdown_entry autoconf_shutdown = {
	.handler = mblty_autoconf_shutdown,
};

void
mblty_autoconf_init()
{
	mblty_register_addr_category(&unicast_category);

	ndisc_register_handler(ND_ROUTER_ADVERT, &autoconf_rtadv_handler);

	mblty_register_shutdown(&autoconf_shutdown);
}

static void
mblty_autoconf_shutdown()
{
	ndisc_unregister_handler(ND_ROUTER_ADVERT, &autoconf_rtadv_handler);
}

void
mblty_prepare_intf_with_def_autoconf(struct mblty_interface *intf)
{
	intf->autoconf = &_def_strategy;
	intf->autoconf_data = allocate_object(mblty_autoconf_data_t);
	debug_assert(intf->autoconf_data, "Failed to allocate autoconf data.");

	intf->autoconf_data->flags = MBLTY_AUTOCONF_F_MANAGED |
				     MBLTY_AUTOCONF_F_PREFIX |
				     MBLTY_AUTOCONF_F_REACH |
				     MBLTY_AUTOCONF_F_GENERATED |
				     MBLTY_AUTOCONF_PF_EARLY_RS;
}

