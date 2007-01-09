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

#ifndef _MBLTY_AUTOCONF_H_
#define _MBLTY_AUTOCONF_H_

#include <mblty/ndisc.h>
#include <mblty/router.h>
#include <mblty/interface.h>

typedef struct mblty_autoconf_data mblty_autoconf_data_t;
typedef struct mblty_autoconf_strategy mblty_autoconf_strategy_t;

struct mblty_autoconf_strategy {
	void (*intf_event)(mblty_interface_t *, mblty_intf_event_t);
	void (*handle_ra)(mblty_interface_t *, ndisc_handler_context_t *);
};

struct mblty_autoconf_data {
/* internaly-managed interface */
#define MBLTY_AUTOCONF_F_MANAGED	0x0001
/* add announced prefixes */
#define MBLTY_AUTOCONF_F_PREFIX		0x0002
/* perform router reachability testing */
#define MBLTY_AUTOCONF_F_REACH		0x0004
/* generate generated addresses */
#define MBLTY_AUTOCONF_F_GENERATED	0x0008
/* autoconf-profile: be optimistic regarding
 * address Duplicate address detection */
#define MBLTY_AUTOCONF_PF_OPTIMISTIC	0x1000
/* autoconf-profile: don't wait for the
 * link local to trigger rtsols */
#define MBLTY_AUTOCONF_PF_EARLY_RS	0x2000
	uint32_t flags;
};

void mblty_autoconf_init();

void mblty_do_std_router_solicit(struct mblty_interface *, struct in6_addr *src);
void mblty_std_handle_ra(struct mblty_interface *, ndisc_handler_context_t *);

void mblty_prepare_intf_with_def_autoconf(struct mblty_interface *);

#endif /* _MBLTY_AUTOCONF_H_ */
