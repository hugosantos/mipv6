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

#ifndef _MOBILITY_REACH_H_
#define _MOBILITY_REACH_H_

#include <netinet/in.h>

#include <mblty/timers.h>
#include <mblty/base-defs.h>
#include <mblty/list-support.h>

struct mblty_reachability_ops {
	void (*reachable)(void *, int linkup);
	void (*unreachable)(void *);
	void (*flags_changed)(void *, uint32_t oldflags);
	void (*permanently_unreachable)(void *);
};

struct mblty_reach_data_ops {
	void (*link_down)(mblty_reach_data_t *);
	void (*link_up)(mblty_reach_data_t *);
	void (*force_check)(mblty_reach_data_t *);
	void (*destructor)(mblty_reach_data_t *);
	int (*is_reachable)(mblty_reach_data_t *);
};

struct mblty_reach_data {
	mblty_os_intf_t *intf;
	struct in6_addr *target;

/* reachability target is a router */
#define MBLTY_REACH_IS_ROUTER	0x0001
#define MBLTY_REACH_PERIODIC	0x0002
	uint32_t flags;

	mblty_reach_data_ops_t *baseops;
	mblty_reachability_ops_t *ops;
	void *instance;

	struct list_entry entry;
};

typedef enum {
	MBLTY_SR_UNKNOWN,
	MBLTY_SR_REACHABLE,
	MBLTY_SR_REACHABLE_QUERYING,
	MBLTY_SR_UNREACHABLE,
	MBLTY_SR_LINKUP_QUERY,
} mblty_standard_reach_state_t;

struct mblty_standard_reach {
	mblty_reach_data_t data;

	suptimer_t period_timer;
	/* in miliseconds */
	int check_period;

	mblty_standard_reach_state_t state;
};

void mblty_release_reach(mblty_reach_data_t *);

mblty_reach_data_t *mblty_alloc_standard_reach(mblty_os_intf_t *,
					       struct in6_addr *target,
					       int isrouter, int periodic);
void mblty_retarget_std_reach(mblty_reach_data_t *, struct in6_addr *);

void mblty_reach_intf_event(mblty_os_intf_t *, int ev);

#endif /* _MOBILITY_REACH_H_ */
