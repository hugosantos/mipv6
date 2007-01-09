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
#include <errno.h>

#include <netinet/ip6mh.h>

#include <mblty/ipsec.h>
#include <mblty/ndisc.h>
#include <mblty/events.h>
#include <mblty/icmpv6.h>
#include <mblty/autoconf.h>
#include <mblty/interface.h>
#include <mblty/base-support.h>

#include <mipv6/ha.h>
#include <mipv6/mipv6.h>
#include <mipv6/console.h>
#include <mipv6/protocol.h>
#include <mipv6/proto-sec.h>

static void ha_interface_event(struct mblty_interface *, int);
static void ha_address_added(mblty_os_intf_t *, struct in6_prefix *);
static void ha_address_removed(mblty_os_intf_t *, struct in6_prefix *);

static int ha_authorize_binding(mipv6_responder_auth_data_t **,
				mipv6_bcache_entry_t *, struct in6_addr *,
				struct in6_addr *, mipv6_msgctx_t *);
static struct mipv6_bcache_entry *ha_create_bcache_entry(struct mipv6_msgctx *);
static void ha_post_create_bcache_entry(struct mipv6_bcache_entry *);
static void ha_binding_changed(struct mipv6_bcache_entry *, int);
static void ha_bcache_entry_expired(struct mipv6_bcache_entry *entry);

static void ha_policy_added(mblty_policy_t *, int);

extern void mipv6_dhaad_init();
extern void mipv6_dhaad_handle_prefix(struct mipv6_home_prefix *);

static LIST_DEF(home_pfxs);

static mipv6_conf_t ha_conf = {
	.ndisc = NDISC_DEFAULT_CONF,
	.debug = {
		.log_file = "mipv6-ha.log",
		.log_level = MIPV6_DEFAULT_LOGLEVEL,
	},
	.conf_file = "ha.conf",
};

static struct {
	int do_hoa_dad;
} mipv6_ha_conf;

static struct mblty_event_ops ha_event_ops = {
	.interface_event = ha_interface_event,
	.address_added = ha_address_added,
	.address_removed = ha_address_removed,
};

struct mipv6_proto_ops mipv6_proto_ops = {
	.authorize_binding = ha_authorize_binding,
	.create_bcache_entry = ha_create_bcache_entry,
	.post_create_bcache_entry = ha_post_create_bcache_entry,
	.binding_changed = ha_binding_changed,
};

static mblty_policy_ops_t ha_bce_pol_ops = {
	.added = ha_policy_added,
};

static mblty_tunnel_factory_t *ha_tun_factory = NULL;
static mipv6_responder_auth_t *ha_resp_auth = NULL;

static void ha_bce_claimed(ndisc_address_record_t *);
static void ha_bce_dad_failed(ndisc_address_record_t *);

static ndisc_address_ops_t ha_bce_ndisc_ops = {
	.claimed = ha_bce_claimed,
	.dad_failed = ha_bce_dad_failed,
};

static inline mblty_interface_t *
ha_bce_intf(struct mipv6_bcache_entry *entry)
{
	return HA_BCE(entry)->homepfx->intf;
}

static struct mipv6_home_prefix *
mipv6_get_home_prefix(struct in6_prefix *p, mblty_interface_t *intf)
{
	struct mipv6_home_prefix *iter;

	list_for_each_entry (iter, &home_pfxs, entry) {
		if (in6_prefix_compare(&iter->pfx, p) != 0)
			continue;

		if (intf && iter->intf != intf)
			continue;

		return iter;
	}

	return NULL;
}

struct mipv6_home_prefix *
mipv6_matching_home_prefix(struct in6_addr *addr)
{
	struct mipv6_home_prefix *iter;

	list_for_each_entry (iter, &home_pfxs, entry) {
		if (in6_prefix_matches(&iter->pfx, addr) == 0)
			return iter;
	}

	return NULL;
}

static struct mipv6_home_prefix *
mipv6_grab_home_prefix(struct in6_addr *addr)
{
	struct mipv6_home_prefix *hpfx = mipv6_matching_home_prefix(addr);
	if (hpfx)
		hpfx->usecount++;
	return hpfx;
}

static void
mipv6_release_home_prefix(struct mipv6_home_prefix *hpfx)
{
	debug_assert(hpfx->usecount > 0,
		     "Releasing home prefix with bad use count");

	hpfx->usecount--;
}

static void
ha_add_home_prefix(struct in6_addr *addr, struct in6_prefix *p,
		   struct mblty_interface *intf)
{
	struct mipv6_home_prefix *hp = mipv6_get_home_prefix(p, NULL);
	char buf1[INET6_PREFIXSTRLEN];

	if (hp == NULL) {
		hp = allocate_object(struct mipv6_home_prefix);
		debug_assert(hp, "Failed to allocate home prefix.");

		/* XXX we take the first address as the HA address */
		in6_addr_copy(&hp->ha_addr, addr);
		in6_prefix_copy(&hp->pfx, p);
		hp->intf = mblty_grab_interface(intf);
		list_add_tail(&hp->entry, &home_pfxs);
		hp->usecount = 0;

		debug_log(1, "HA handles Home prefix %s at %s.\n",
			  format_prefix(buf1, p), intf->osh->name);

		mipv6_dhaad_handle_prefix(hp);

		mblty_os_intf_enable(intf->osh, MBLTY_OS_INTF_CAP_FORWARDING);
	} else if (hp->intf != intf) {
		debug_log(0, "Home prefix %s is configured to %s and to %s."
			     " Ignoring %s.\n", format_prefix(buf1, p),
			     hp->intf->osh->name, intf->osh->name,
			     intf->osh->name);
	}
}

static void
ha_address_added(mblty_os_intf_t *osh, struct in6_prefix *p)
{
	mblty_link_local_t *linklocal;
	mblty_interface_t *intf;
	struct in6_prefix pfx;

	if (p->prefixlen == 128 ||
	    memcmp(&p->address, &in6addr_loopback, 16) == 0)
		return;

	intf = mblty_get_interface(osh);
	if (intf == NULL)
		return;

	if (IN6_IS_ADDR_LINKLOCAL(&p->address)) {
		linklocal = mblty_allocate_linklocal(intf, &p->address, 0);
		if (linklocal)
			mblty_link_linklocal(linklocal);
	} else {
		in6_prefix_copy_applied(&pfx, p);

		ha_add_home_prefix(&p->address, &pfx, intf);
	}

	mblty_put_interface(intf);
}

static void
ha_kill_home_prefix(struct mipv6_home_prefix *hp)
{
	mblty_os_intf_disable(hp->intf->osh,
			      MBLTY_OS_INTF_CAP_FORWARDING);
	mblty_put_interface(hp->intf);
	list_del(&hp->entry);

	free_object(hp);
}

static void
ha_populate_intf(mblty_os_intf_t *osh, struct in6_prefix *addr, void *arg)
{
	ha_address_added(osh, addr);
}

static int
ha_remove_bcache_entry_with_hpfx(struct mipv6_bcache_entry *entry, void *arg)
{
	struct mipv6_ha_bcache_entry *data = HA_BCE(entry);
	struct mipv6_home_prefix *hpfx = arg;

	if ((entry->flags & MIPV6_BCE_HOME_REG) && (data->homepfx == hpfx))
		mipv6_bcache_remove_entry(entry);

	return 0;
}

static void
ha_remove_home_prefix(struct mipv6_home_prefix *hp)
{
	mipv6_foreach_bcache_entry(ha_remove_bcache_entry_with_hpfx, hp);
	ha_kill_home_prefix(hp);
}

static void
ha_address_removed(mblty_os_intf_t *osh, struct in6_prefix *p)
{
	mblty_interface_t *intf = mblty_get_interface(osh);
	struct mipv6_home_prefix *hp;
	struct in6_prefix pfx;

	if (intf == NULL)
		return;

	if (IN6_IS_ADDR_LINKLOCAL(&p->address)) {
		mblty_link_local_t *ll = mblty_get_linklocal(intf, &p->address);
		if (ll)
			mblty_remove_linklocal(ll);
	} else {
		in6_prefix_copy_applied(&pfx, p);

		hp = mipv6_get_home_prefix(&pfx, intf);
		if (hp)
			ha_remove_home_prefix(hp);
	}

	mblty_put_interface(intf);
}

static void
ha_interface_event(struct mblty_interface *intf, int event)
{
	struct mipv6_home_prefix *pfx, *safe;

	switch (event) {
	case MBLTY_INTF_EV_PREP:
		mblty_os_intf_get_addresses(intf->osh, ha_populate_intf, NULL);
		mblty_prepare_intf_with_def_autoconf(intf);
		intf->autoconf_data->flags = MBLTY_AUTOCONF_F_PREFIX;
		break;

	case MBLTY_INTF_EV_REMOVING:
		list_for_each_entry_safe (pfx, safe, &home_pfxs, entry) {
			if (pfx->intf == intf)
				ha_remove_home_prefix(pfx);
		}
		break;
	}
}

static void
ha_fill_bce_pol(struct mipv6_ha_bcache_entry *entry,
		struct in6_prefix *pfx)
{
	in6_addr_copy(&pfx->address, &entry->bce.hoa);
	pfx->prefixlen = 128;

	entry->hostroute.destination = pfx;
}

static void
ha_bcache_entry_destructor(struct mipv6_bcache_entry *entry)
{
	struct mipv6_ha_bcache_entry *data = HA_BCE(entry);
	struct in6_prefix pfx;

	ha_fill_bce_pol(data, &pfx);
	mblty_delete_policy(&data->hostroute);

	/* entry expired, we must free resources */
	if (data->tun) {
		mblty_tunnel_release(data->tun);
		data->tun = NULL;
	}

	if (!mblty_os_intf_is_loopback(data->homepfx->intf->osh))
		ndisc_addr_unregister(&data->nar);
	mipv6_release_home_prefix(data->homepfx);
	data->homepfx = NULL;

	free_object(entry);
}

static void
ha_bcache_entry_expired(struct mipv6_bcache_entry *entry)
{
	char buf1[INET6_ADDRSTRLEN];

	debug_log(1, "The registration for Mobile Node %s expired.\n",
		  format_addr(buf1, &entry->hoa));
}

static int
ha_authorize_binding(mipv6_responder_auth_data_t **auth,
		     mipv6_bcache_entry_t *entry, struct in6_addr *hoa,
		     struct in6_addr *coa, mipv6_msgctx_t *msgctx)
{
	struct ip6_mh_binding_update *msg = msgctx->u.raw;

	if (ntohs(msg->ip6mhbu_flags) & IP6_MH_BU_HOME) {
		if (mipv6_matching_home_prefix(hoa) == NULL)
			return IP6_MH_BAS_NOT_HOME_SUBNET;

		/* XXX accepting any binding */
		return IP6_MH_BAS_ACCEPTED;
	} else {
		/* already had a BC entry with an home registration? */
		if (entry && (entry->flags & MIPV6_BCE_HOME_REG))
			return -1;

		return ha_resp_auth->ops->auth_bu(ha_resp_auth, auth, hoa, coa,
						  msgctx);
	}
}

static void
ha_bce_dad_failed(ndisc_address_record_t *nar)
{
	struct mipv6_bcache_entry *entry;
	char buf1[INET6_ADDRSTRLEN];

	entry = &container_of(nar, struct mipv6_ha_bcache_entry, nar)->bce;

	debug_log(3, "Address resolution for %s failed, duplicate "
		     "address, reporting.\n", format_addr(buf1, &entry->hoa));

	mipv6_bcache_remove_entry_with_error(entry, IP6_MH_BAS_DAD_FAILED);
}

static void
ha_bce_claimed(ndisc_address_record_t *nar)
{
	struct mipv6_bcache_entry *entry;
	char buf1[INET6_ADDRSTRLEN];

	entry = &container_of(nar, struct mipv6_ha_bcache_entry, nar)->bce;

	if (!(entry->flags & MIPV6_BCE_PENDING_UPD))
		return;

	debug_log(3, "Address resolution for %s didn't return any "
		     "nodes, proceeding.\n", format_addr(buf1, &entry->hoa));

	mipv6_bcache_no_longer_pending(entry);
}

static struct mipv6_bcache_entry *
ha_create_bcache_entry(struct mipv6_msgctx *msg)
{
	struct ip6_mh_binding_update *bu = msg->u.raw;
	struct mipv6_ha_bcache_entry *hae;
	struct mipv6_bcache_entry *entry;
	struct mipv6_home_prefix *hpfx;
	mblty_address_t *hoa;
	int res;

	if (!(ntohs(bu->ip6mhbu_flags) & IP6_MH_BU_HOME))
		return mipv6_create_bcache_entry(msg);

	hpfx = mipv6_grab_home_prefix(msg->hoa);
	if (hpfx == NULL)
		return NULL;

	hae = allocate_object(struct mipv6_ha_bcache_entry);
	if (hae == NULL) {
		mipv6_release_home_prefix(hpfx);
		return NULL;
	}

	if (!mblty_os_intf_is_loopback(hpfx->intf->osh)) {
		hoa = mblty_hard_get_address(msg->hoa);
		if (hoa == NULL) {
			free_object(hae);
			mipv6_release_home_prefix(hpfx);
			return NULL;
		}

		res = ndisc_addr_register(&hae->nar, hpfx->intf, hoa,
					  &ha_bce_ndisc_ops);
		mblty_put_address(hoa);

		if (res < 0) {
			free_object(hae);
			mipv6_release_home_prefix(hpfx);
			return NULL;
		}

		hae->nar.flags = NDISC_ADDRREC_F_NOISY;
	}

	entry = &hae->bce;

	mipv6_prepare_bcache_entry(entry, msg->hoa, msg->to);
	entry->flags |= MIPV6_BCE_HOME_REG;
	entry->cb_destructor = ha_bcache_entry_destructor;
	entry->cb_entry_expired = ha_bcache_entry_expired;

	hae->tun = NULL;
	hae->homepfx = hpfx;
	hae->state = MIPV6_HA_BC_UNKNOWN;

	mblty_init_policy(&hae->hostroute);
	hae->hostroute.ops = &ha_bce_pol_ops;

	return entry;
}

static void
ha_post_create_bcache_entry(struct mipv6_bcache_entry *entry)
{
	struct mipv6_ha_bcache_entry *data = HA_BCE(entry);

	if (!(entry->flags & MIPV6_BCE_HOME_REG))
		return;

	if (mipv6_ha_conf.do_hoa_dad &&
	    !mblty_os_intf_is_loopback(ha_bce_intf(entry)->osh)) {
		data->nar.flags |= NDISC_ADDRREC_F_NEEDS_DAD;
		entry->flags |= MIPV6_BCE_PENDING_UPD;
	}

	if (!mblty_os_intf_is_loopback(data->homepfx->intf->osh))
		ndisc_addr_proceed(&data->nar);
}

static void
ha_policy_added(mblty_policy_t *pol, int res)
{
	struct mipv6_ha_bcache_entry *data =
		container_of(pol, struct mipv6_ha_bcache_entry, hostroute);

	debug_log(2, "Added route to mobile node via %s (res = %i).\n",
		  data->tun->osh->name, res);

	debug_assert(data->state == MIPV6_HA_BC_ROUTE_PENDING,
		     "Critical HA BCE FSM failure");

	if (res < 0) {
		/* :-( handle errors */
		return;
	}

	data->state = MIPV6_HA_BC_STABLE;
}

static void
ha_enable_onbehalf(struct mipv6_bcache_entry *entry)
{
	struct mipv6_ha_bcache_entry *data = HA_BCE(entry);
	mblty_policy_t *pol = &data->hostroute;
	struct in6_prefix pfx;

	if (data->tun == NULL) {
		data->tun = mblty_tunnel_alloc(ha_tun_factory, &entry->local,
					       &entry->coa);
		if (data->tun == NULL)
			return;

		if (mblty_os_intf_set_up(data->tun->osh, 1) < 0)
			perror("Failed to set_interface_up");

		mblty_os_intf_enable(data->tun->osh,
				     MBLTY_OS_INTF_CAP_FORWARDING);
		mblty_os_intf_disable(data->tun->osh,
				      MBLTY_OS_INTF_CAP_AUTOCONF);
	}

	data->state = MIPV6_HA_BC_ROUTE_PENDING;

	ha_fill_bce_pol(data, &pfx);
	pol->intf = data->tun->osh;

	mblty_add_policy(pol);

	pol->destination = NULL;
}

static void
ha_binding_changed(struct mipv6_bcache_entry *entry, int wasvalid)
{
	struct mipv6_ha_bcache_entry *data = HA_BCE(entry);

	/* Is it an home registration? */
	if (!(entry->flags & MIPV6_BCE_HOME_REG))
		return;

	/* either create the tunnel to the MN or update the existing one */
	if (data->tun == NULL)
		ha_enable_onbehalf(entry);
	else
		mblty_tunnel_update(data->tun, &entry->local, &entry->coa);
}

static void
ha_configure_interface(mipv6_conf_item_t *item, char *args[], int argcount)
{
	mblty_os_intf_t *osh = mblty_os_intf_get_by_name(args[1]);

	if (osh == NULL || mblty_create_interface(osh, 0, 0) == NULL)
		perform_shutdown("Failed to instantiate interface '%s'",
				 args[1]);
}

static void
ha_enable_or_disable(mipv6_conf_item_t *item, char *args[], int argcount)
{
	int enable = 1;

	if (strcmp(args[0], "disable") == 0)
		enable = 0;

	if (strcmp(args[1], "homelink-dad") == 0)
		mipv6_ha_conf.do_hoa_dad = enable;
	else
		perform_shutdown("Unrecognized option '%s'", args[1]);
}

static mipv6_conf_item_t ha_conf_items[] = {
	{
		.name = "interface",
		.params = { MIPV6_PARAM_T_IDENTIFIER },
		.handler = ha_configure_interface,
	},
	{
		.name = "enable",
		.params = { MIPV6_PARAM_T_IDENTIFIER },
		.handler = ha_enable_or_disable,
	},
	{
		.name = "disable",
		.params = { MIPV6_PARAM_T_IDENTIFIER },
		.handler = ha_enable_or_disable,
	},
	{
		.name = NULL,
	}
};

static void
mipv6_ha_shutdown()
{
	if (ha_resp_auth) {
		ha_resp_auth->ops->release(ha_resp_auth);
		ha_resp_auth = NULL;
	}

	mblty_return_tunnel_factory(ha_tun_factory);
	ha_tun_factory = NULL;
}

static struct mblty_shutdown_entry ha_shutdown = {
	.handler = mipv6_ha_shutdown,
};

static void
mipv6_ha_init()
{
	debug_log(0, "\n");
	debug_log(0, " ><>\n");
	debug_log(0, "><>  Home Agent implementation (RFC 3775).\n");
	debug_log(0, " ><>\n");
	debug_log(0, "\n");

	ipsec_init();
	icmpv6_protocol_init();
	ndisc_init(&ha_conf.ndisc);
	mblty_autoconf_init();

	ha_tun_factory = mblty_obtain_tunnel_factory(MBLTY_TUN_TYPE_IP6IP6);
	if (ha_tun_factory == NULL)
		perform_shutdown("IPv6-over-IPv6 tunnels not available.");

	ha_resp_auth = mipv6_rr_obtain_resp_auth();
	debug_assert(ha_resp_auth, "Failed to obtain RR responder auth.");

	mblty_register_shutdown(&ha_shutdown);

	mipv6_protocol_init();
	mipv6_rconsole_init();

	mipv6_dhaad_init();

	parse_configuration(ha_conf.conf_file, ha_conf_items);

	if (mblty_interface_count() == 0)
		perform_shutdown("No home network interfaces configured.");
}

int
main(int argc, char *argv[])
{
	mipv6_parse_options(argc, argv, &ha_conf);
	mipv6_init_program(&ha_conf, &ha_event_ops);
	mipv6_ha_init();
	return mblty_main_loop();
}

