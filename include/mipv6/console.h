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

#ifndef _MIPV6_PRIV_CONSOLE_H_
#define _MIPV6_PRIV_CONSOLE_H_

struct mipv6_rconsole_client;

typedef int (*mipv6_console_cmd_cb)(struct mipv6_rconsole_client *);

struct mipv6_console_cmd {
	const char *regex;
	mipv6_console_cmd_cb cmd_cb;
};

void mipv6_rconsole_init();

void mipv6_rconsole_remove_client(struct mipv6_rconsole_client *);
int mipv6_rconsole_exit(struct mipv6_rconsole_client *);

void con_printf(struct mipv6_rconsole_client *, const char *, ...);

#endif /* _MIPV6_PRIV_CONSOLE_H_ */
