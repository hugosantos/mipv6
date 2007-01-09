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

#include <mipv6/ha.h>
#include <mipv6/os.h>
#include <mipv6/console.h>
#include <mipv6/protocol.h>

const char *mipv6_console_path = "/var/run/mipv6-ha-console";

extern int rc_show_timers(struct mipv6_rconsole_client *);
extern int rc_show_routers(struct mipv6_rconsole_client *);
extern int rc_show_prefixes(struct mipv6_rconsole_client *);
extern int rc_show_addresses(struct mipv6_rconsole_client *);
extern int rc_show_interfaces(struct mipv6_rconsole_client *);

static int
print_bcache_entry(struct mipv6_bcache_entry *bcentry, void *arg)
{
	struct mipv6_rconsole_client *cli = arg;
	char buf1[INET6_ADDRSTRLEN], buf2[INET6_ADDRSTRLEN],
	     buf3[INET6_ADDRSTRLEN];

	con_printf(cli, "(%s, %s, %s) lifetime: %u seq: %u flags: %u\n",
		   format_addr(buf1, &bcentry->local),
		   format_addr(buf2, &bcentry->hoa),
		   format_addr(buf3, &bcentry->coa),
		   (uint32_t)bcentry->lifetime, (uint32_t)bcentry->sequence,
		   (uint32_t)bcentry->flags);

	if (bcentry->flags & MIPV6_BCE_HOME_REG) {
		struct mipv6_ha_bcache_entry *hadata = HA_BCE(bcentry);
		con_printf(cli, "   State: %i Tunnel: %s\n", hadata->state,
			   hadata->tun ? hadata->tun->osh->name : NULL);
	}

	return 0;
}

static int
show_binding_cache(struct mipv6_rconsole_client *cli)
{
	mipv6_foreach_bcache_entry(print_bcache_entry, cli);
	return 0;
}

struct mipv6_console_cmd mipv6_console_cmds[] = {
	{ "^exit$", mipv6_rconsole_exit },
	{ "^show[ \t]+timers$", rc_show_timers },
	{ "^show[ \t]+routers$", rc_show_routers },
	{ "^show[ \t]+prefixes$", rc_show_prefixes },
	{ "^show[ \t]+addresses$", rc_show_addresses },
	{ "^show[ \t]+interfaces$", rc_show_interfaces },
	{ "^show[ \t]+bcache$", show_binding_cache },
	{ "^show[ \t]+binding[ \t]+cache$", show_binding_cache },
	{ NULL, NULL }
};

