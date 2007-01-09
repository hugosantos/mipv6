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
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <netinet/ip6mh.h>

#include <mblty/ipsec.h>
#include <mblty/ndisc.h>
#include <mblty/events.h>
#include <mblty/icmpv6.h>
#include <mblty/autoconf.h>
#include <mblty/interface.h>
#include <mblty/base-support.h>

#include <mipv6/os.h>
#include <mipv6/mipv6.h>
#include <mipv6/mn-hoa.h>
#include <mipv6/console.h>
#include <mipv6/protocol.h>
#include <mipv6/proto-sec.h>

extern void mipv6_helper_init();

extern void mipv6_mn_ask_helper_new_interface(mblty_os_intf_t *);
extern void mipv6_mn_ask_helper_ro(struct in6_addr *, struct in6_addr *);

static void mn_interface_event(struct mblty_interface *, int);
static void mn_found_interface(mblty_os_intf_t *);
static void mn_available_address(mblty_network_address_t *);

static int
mipv6_mn_authorize_binding(mipv6_responder_auth_data_t **auth,
			   mipv6_bcache_entry_t *entry, struct in6_addr *hoa,
			   struct in6_addr *coa, mipv6_msgctx_t *);
static void mipv6_mn_bcache_miss(struct in6_addr *, struct in6_addr *);

static struct mblty_event_ops mn_event_ops = {
	.found_interface = mn_found_interface,
	.interface_event = mn_interface_event,
	.address_available = mn_available_address,
	.address_lost = mipv6_mn_lost_address,
};

struct mipv6_proto_ops mipv6_proto_ops = {
	.authorize_binding = mipv6_mn_authorize_binding,
	.bcache_miss = mipv6_mn_bcache_miss,
};

static mipv6_conf_t mn_conf = {
	.ndisc = NDISC_DEFAULT_CONF,
	.debug = {
		.log_file = "mipv6-mn.log",
		.log_level = MIPV6_DEFAULT_LOGLEVEL,
	},
	.conf_file = "mn.conf",
};

static struct {
	int force_no_dad;
} mipv6_mn_conf = {
	.force_no_dad = 0,
};

static mipv6_responder_auth_t *mn_resp_auth = NULL;

void
mn_found_interface(mblty_os_intf_t *osh)
{
	mipv6_mn_ask_helper_new_interface(osh);
}

static void
mn_interface_event(mblty_interface_t *intf, int event)
{
	switch (event) {
	case MBLTY_INTF_EV_PREP:
		/* we are past interface allocation */
		mblty_prepare_intf_with_def_autoconf(intf);
		break;

	case MBLTY_INTF_EV_DELETED:
		mblty_os_intf_enable(intf->osh, MBLTY_OS_INTF_CAP_AUTOCONF);
		break;

	default:
		break;
	}
}

static void
mn_available_address(mblty_network_address_t *addr)
{
	if (IN6_IS_ADDR_LINKLOCAL(mblty_get_addr(addr)))
		return;

	if (mblty_interface_has_link(mblty_addr_intf(addr)))
		mipv6_mn_distribute_address(addr);
}

int
mipv6_mn_authorize_binding(mipv6_responder_auth_data_t **auth,
			   mipv6_bcache_entry_t *entry, struct in6_addr *hoa,
			   struct in6_addr *coa, mipv6_msgctx_t *ctx)
{
	struct ip6_mh_binding_update *bu = ctx->u.raw;

	if (ntohs(bu->ip6mhbu_flags) & IP6_MH_BU_HOME)
		return IP6_MH_BAS_HA_NOT_SUPPORTED;

	return mn_resp_auth->ops->auth_bu(mn_resp_auth, auth, hoa, coa, ctx);
}

static void
mipv6_mn_bcache_miss(struct in6_addr *local, struct in6_addr *remote)
{
	struct mipv6_mn_hoa *hoa = mipv6_mn_get_hoa(local);
	struct mipv6_mn_individual *ind;

	if (hoa == NULL || hoa->flags & MIPV6_MN_HOA_NO_RO)
		return;

	if ((ind = mipv6_mn_hoa_get_individual(hoa, remote)) == NULL) {
		/* create a new locked individual */
		if ((ind = mipv6_mn_hoa_alloc_individual(hoa, remote)) == NULL)
			return;

		mipv6_mn_ask_helper_ro(local, remote);
	} else {
		mipv6_mn_individual_is_required(ind);
	}
}

static void
mn_configure_interface(mipv6_conf_item_t *item, char *args[], int argcount)
{
	mblty_os_intf_t *osh = mblty_os_intf_get_by_name(args[1]);

	if (osh == NULL || mblty_create_interface(osh, 0, 0) == NULL)
		perform_shutdown("Failed to instantiate interface '%s'",
				 args[1]);
}

static void
parse_prefix(struct in6_prefix *p, const char *in)
{
	char buf[INET6_PREFIXSTRLEN], *sep;
	int len;

	len = strlen(in);
	if (len >= INET6_PREFIXSTRLEN)
		len = INET6_PREFIXSTRLEN - 1;

	strncpy(buf, in, len);
	buf[len] = 0;

	p->prefixlen = 128;

	sep = strchr(buf, '/');
	if (sep) {
		(*sep) = 0;
		sep++;
		p->prefixlen = atoi(sep);
	}

	inet_pton(AF_INET6, buf, &p->address);
}

static void
mn_configure_hoa(mipv6_conf_item_t *item, char *args[], int argcount)
{
	struct addrinfo hints, *res;
	struct sockaddr_in6 *addr;
	struct in6_prefix pfx;
	int ret;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET6;

	ret = getaddrinfo(args[1], NULL, &hints, &res);
	if (ret != 0)
		perform_shutdown("Failed to resolve `%s`", args[1]);

	addr = (struct sockaddr_in6 *)res->ai_addr;

	parse_prefix(&pfx, args[2]);

	mipv6_mn_allocate_hoa(&addr->sin6_addr, &pfx, &pfx.address, 0);

	freeaddrinfo(res);
}

static void
mn_set_hoa_nai(mipv6_conf_item_t *item, char *args[], int argcount)
{
	struct mipv6_mn_hoa *hoa;
	struct in6_addr addr;

	inet_pton(AF_INET6, args[1], &addr);

	hoa = mipv6_mn_get_hoa(&addr);
	if (hoa == NULL)
		perform_shutdown("No such HoA %s", args[1]);

	mipv6_mn_hoa_set_nai(hoa, args[2]);
}

static void
mn_enable_or_disable(mipv6_conf_item_t *item, char *args[], int argcount)
{
	int enable = 1;

	if (strcmp(args[0], "disable") == 0)
		enable = 0;

	if (strcmp(args[1], "dad") == 0)
		mipv6_mn_conf.force_no_dad = !enable;
	else
		perform_shutdown("Unrecognized option '%s'", args[1]);
}

static void
mn_hoa_set(mipv6_conf_item_t *item, char *args[], int argcount)
{
	struct mipv6_mn_hoa *hoa;
	struct in6_addr addr;
	int value;

	inet_pton(AF_INET6, args[1], &addr);

	hoa = mipv6_mn_get_hoa(&addr);
	if (hoa == NULL)
		perform_shutdown("No such HoA %s", args[1]);

	value = (strcmp(args[3], "on") == 0);

	if (strcmp(args[2], "ha-ipsec-auth") == 0) {
		mipv6_mn_hoa_set_ipsec_auth(hoa, value);
	} else if (strcmp(args[2], "ha-ipsec-dynamic-keying") == 0) {
		debug_log(0, "UNIMPLEMENTED, must talk with IKE daemon.\n");
	} else if (strcmp(args[2], "route-opt") == 0) {
		if (value)
			hoa->flags &= ~MIPV6_MN_HOA_NO_RO;
		else
			hoa->flags |=  MIPV6_MN_HOA_NO_RO;
	} else {
		perform_shutdown("Unrecognized option '%s'", args[2]);
	}
}

static mipv6_conf_item_t mn_conf_items[] = {
	{
		.name = "interface",
		.params = { MIPV6_PARAM_T_IDENTIFIER },
		.handler = mn_configure_interface,
	},
	{
		.name = "home-def",
		.params = { MIPV6_PARAM_T_DOMAIN, MIPV6_PARAM_T_PREFIX },
		.handler = mn_configure_hoa,
	},
	{
		.name = "home-ident",
		.params = { MIPV6_PARAM_T_ADDRESS, MIPV6_PARAM_T_NAI },
		.handler = mn_set_hoa_nai,
	},
	{
		.name = "enable",
		.params = { MIPV6_PARAM_T_IDENTIFIER },
		.handler = mn_enable_or_disable,
	},
	{
		.name = "disable",
		.params = { MIPV6_PARAM_T_IDENTIFIER },
		.handler = mn_enable_or_disable,
	},
	{
		.name = "set",
		.params = { MIPV6_PARAM_T_ADDRESS, MIPV6_PARAM_T_IDENTIFIER,
			    MIPV6_PARAM_T_ONOFF },
		.handler = mn_hoa_set,
	},
	{
		.name = NULL,
	}
};

static void
mipv6_mn_init()
{
	debug_log(0, "\n");
	debug_log(0, " <><\n");
	debug_log(0, "<><  Mobile Node implementation (RFC 3775).\n");
	debug_log(0, " <><\n");
	debug_log(0, "\n");

	ipsec_init();

	icmpv6_protocol_init();
	ndisc_init(&mn_conf.ndisc);
	mblty_autoconf_init();

	mipv6_protocol_init();
	mipv6_rconsole_init();
	mipv6_helper_init();

	mn_resp_auth = mipv6_rr_obtain_resp_auth();
	debug_assert(mn_resp_auth, "Failed to obtain RR responder auth.");

	mipv6_mn_state_init();

	parse_configuration(mn_conf.conf_file, mn_conf_items);
}

int
main(int argc, char *argv[])
{
	mipv6_parse_options(argc, argv, &mn_conf);
	mipv6_init_program(&mn_conf, &mn_event_ops);
	mipv6_mn_init();
	return mblty_main_loop();
}

