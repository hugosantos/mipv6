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
#include <mblty/timers.h>
#include <mblty/interface.h>
#include <mipv6/os.h>
#include <mipv6/console.h>
#include <mipv6/protocol.h>

int rc_show_timers(struct mipv6_rconsole_client *);
int rc_show_routers(struct mipv6_rconsole_client *);
int rc_show_prefixes(struct mipv6_rconsole_client *);
int rc_show_addresses(struct mipv6_rconsole_client *);
int rc_show_interfaces(struct mipv6_rconsole_client *);
int rc_show_binding_cache(struct mipv6_rconsole_client *);

static void
print_timer_header(struct mipv6_rconsole_client *cli)
{
	con_printf(cli, " %32s %10s %10s\n", "timer name", "interval",
		   "remaining");
	con_printf(cli, " -------------------------------------------------------\n");
}

static void
print_timer(suptimer_t *tmr, void *arg)
{
	uint64_t now = support_get_sys_timestamp();
	struct mipv6_rconsole_client *cli = arg;
	int diff;

	if (now < tmr->target)
		diff = tmr->target - now;
	else
		diff = 0;

	if (tmr->interval > 3600000)
		con_printf(cli, " %32s %8ih  %8is\n", tmr->name,
			   tmr->interval / 3600000, diff / 1000);
	else
		con_printf(cli, " %32s %8ims %8ims\n", tmr->name,
			   tmr->interval, diff);
}

int
rc_show_timers(struct mipv6_rconsole_client *cli)
{
	print_timer_header(cli);
	support_foreach_timer(print_timer, cli);
	return 0;
}

static void
print_link_addr(struct mipv6_rconsole_client *cli,
		struct mblty_link_addr *addr)
{
	int i;

	con_printf(cli, "%02x", addr->addr[0]);

	for (i = 1; i < addr->length; i++) {
		con_printf(cli, ":%02x", addr->addr[i]);
	}
}

static void
print_router(struct mblty_router *rtr, void *arg)
{
	char buf1[INET6_ADDRSTRLEN], buf2[INET6_PREFIXSTRLEN];
	struct mblty_interface *intf = mblty_rtr_intf(rtr);
	struct mipv6_rconsole_client *cli = arg;
	struct mblty_router_prefix *netpfx;

	con_printf(cli, "Router %s\n", format_addr(buf1, mblty_rtr_address(rtr)));
	con_printf(cli, "  Interface: %s\n", intf ? intf->osh->name : NULL);

	if (rtr->link_addr) {
		con_printf(cli, "  Link-addr: ");
		print_link_addr(cli, rtr->link_addr);
		con_printf(cli, "\n");
	}

	con_printf(cli, "  Prefixes:\n");
	list_for_each_entry (netpfx, &rtr->prefixes, entry) {
		con_printf(cli, "    %s\n", format_prefix(buf2,
			   mblty_get_rtr_pfx(netpfx)));
	}
}

int
rc_show_routers(struct mipv6_rconsole_client *cli)
{
	mblty_foreach_router(print_router, cli);
	return 0;
}

static void
print_prefix(struct mblty_prefix *pfx, void *arg)
{
	struct mipv6_rconsole_client *cli = arg;
	char buf1[INET6_PREFIXSTRLEN];

	con_printf(cli, "Prefix %s\n", format_prefix(buf1, &pfx->prefix));
}

int
rc_show_prefixes(struct mipv6_rconsole_client *cli)
{
	mblty_foreach_prefix(print_prefix, cli);
	return 0;
}

static void
print_address(struct mblty_address *addr, void *arg)
{
	struct mipv6_rconsole_client *cli = arg;
	char buf1[INET6_ADDRSTRLEN];

	con_printf(cli, "Address %s\n", format_addr(buf1, &addr->address));
}

int
rc_show_addresses(struct mipv6_rconsole_client *cli)
{
	mblty_foreach_address(print_address, cli);
	return 0;
}

static void
print_eui64(struct mipv6_rconsole_client *cli, mblty_eui64_t *eui64)
{
	int i;

	con_printf(cli, "%02X", eui64->data[0]);

	for (i = 1; i < 8; i++)
		con_printf(cli, "-%02X", eui64->data[i]);
}

static void
print_interface(mblty_interface_t *intf, void *arg)
{
	struct mipv6_rconsole_client *cli = arg;
	char buf1[INET6_PREFIXSTRLEN], d[64];
	mblty_intf_prefix_t *intfpfx;
	mblty_router_t *rtr;

	con_printf(cli, "Interface %s\n",
		   mblty_os_intf_desc(intf->osh, 1, d, sizeof(d)));
	con_printf(cli, "  EUI-64: ");
	print_eui64(cli, &intf->eui64);
	con_printf(cli, "\n");

	con_printf(cli, "  Prefixes:\n");
	list_for_each_entry (intfpfx, &intf->prefixes, entry) {
		con_printf(cli, "    %s\n",
			   format_prefix(buf1, &intfpfx->parent->prefix));
	}

	con_printf(cli, "  Routers:\n");
	list_for_each_entry (rtr, &intf->routers, entry) {
		con_printf(cli, "    %s\n",
			   format_addr(buf1, mblty_rtr_address(rtr)));
	}
}

int
rc_show_interfaces(struct mipv6_rconsole_client *cli)
{
	mblty_foreach_interface(print_interface, cli);
	return 0;
}

static int
print_bcache_entry(struct mipv6_bcache_entry *bcentry, void *arg)
{
	char buf1[INET6_ADDRSTRLEN], buf2[INET6_ADDRSTRLEN],
	     buf3[INET6_ADDRSTRLEN];
	struct mipv6_rconsole_client *cli = arg;

	con_printf(cli, "(%s, %s, %s) lifetime: %u seq: %u flags: %u\n",
		   format_addr(buf1, &bcentry->local),
		   format_addr(buf2, &bcentry->hoa),
		   format_addr(buf3, &bcentry->coa),
		   (uint32_t)bcentry->lifetime, (uint32_t)bcentry->sequence,
		   (uint32_t)bcentry->flags);

	return 0;
}

int
rc_show_binding_cache(struct mipv6_rconsole_client *cli)
{
	mipv6_foreach_bcache_entry(print_bcache_entry, cli);
	return 0;
}

