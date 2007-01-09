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
#include <mblty/reach.h>
#include <mblty/icmpv6.h>
#include <mblty/interface.h>
#include <mblty/base-support.h>

#define DEFAULT_REACH_TIMEOUT	120

static LIST_DEF(reach_table);

static void std_reach_nud_result(ndisc_nud_result_t *, void *);

static void std_reach_link_down(mblty_reach_data_t *);
static void std_reach_link_up(mblty_reach_data_t *);
static void std_reach_force_check(mblty_reach_data_t *);
static void std_reach_destructor(mblty_reach_data_t *);
static int std_reach_is_reachable(mblty_reach_data_t *);

static const char *std_state_names[] = {
	"Unknown",
	"Reachable",
	"Reachable (Querying)",
	"Unreachable",
	"Querying (LinkUp)",
};

static mblty_reach_data_ops_t std_reach_data_ops = {
	.link_down = std_reach_link_down,
	.link_up = std_reach_link_up,
	.force_check = std_reach_force_check,
	.destructor = std_reach_destructor,
	.is_reachable = std_reach_is_reachable,
};

static void
std_reach_change_state(struct mblty_standard_reach *r,
		       mblty_standard_reach_state_t state, int intmrhandle)
{
	mblty_standard_reach_state_t old = r->state;
	char buf1[INET6_ADDRSTRLEN];

	if (r->state == state)
		return;

	debug_log(4, "Reachability watcher for %s changed state: %s -> %s.\n",
		  format_addr(buf1, r->data.target), std_state_names[r->state],
		  std_state_names[state]);

	r->state = state;

	if (old == MBLTY_SR_REACHABLE && !intmrhandle) {
		if (r->data.flags & MBLTY_REACH_PERIODIC)
			timer_remove(&r->period_timer);
	}

	switch (state) {
	case MBLTY_SR_UNKNOWN:
		break;
	case MBLTY_SR_REACHABLE:
		if (old == MBLTY_SR_UNREACHABLE
		    || old == MBLTY_SR_LINKUP_QUERY)
			r->data.ops->reachable(r->data.instance,
					       old == MBLTY_SR_LINKUP_QUERY);
		if (r->data.flags & MBLTY_REACH_PERIODIC)
			timer_add(&r->period_timer, r->check_period);
		break;
	case MBLTY_SR_UNREACHABLE:
		r->data.ops->unreachable(r->data.instance);
		break;
	case MBLTY_SR_LINKUP_QUERY:
	case MBLTY_SR_REACHABLE_QUERYING:
		ndisc_perform_nud(r->data.intf, r->data.target,
				  std_reach_nud_result, r);
		break;
	}
}

static inline struct mblty_standard_reach *
std_reach_of(struct mblty_reach_data *data)
{
	return container_of(data, struct mblty_standard_reach, data);
}

static void
std_reach_check_cancel_pending(struct mblty_standard_reach *r)
{
	if (r->state == MBLTY_SR_LINKUP_QUERY ||
	    r->state == MBLTY_SR_REACHABLE_QUERYING) {
		ndisc_cancel_nud(std_reach_nud_result, r);
	}
}

static void
std_reach_link_down(struct mblty_reach_data *data)
{
	/* check if the link is going down in the middle of request */
	std_reach_check_cancel_pending(std_reach_of(data));
	std_reach_change_state(std_reach_of(data), MBLTY_SR_UNREACHABLE, 0);
}

static void
std_reach_mark_reachable(struct mblty_standard_reach *r, int isrouter)
{
	uint32_t oldflags = r->data.flags;

	if (isrouter)
		r->data.flags |= MBLTY_REACH_IS_ROUTER;
	else
		r->data.flags &= ~MBLTY_REACH_IS_ROUTER;

	std_reach_change_state(r, MBLTY_SR_REACHABLE, 0);

	if (r->data.ops == NULL || r->data.ops->flags_changed == NULL)
		return;

	if (r->data.flags != oldflags) {
		r->data.ops->flags_changed(r->data.instance, oldflags);
	}
}

static void
std_reach_nud_result(ndisc_nud_result_t *res, void *param)
{
	mblty_standard_reach_t *r = param;

	if (res->result == NDISC_NUD_RES_REACHABLE) {
		std_reach_mark_reachable(r, res->flags & ND_NA_FLAG_ROUTER);
	} else {
		std_reach_change_state(r, MBLTY_SR_UNREACHABLE, 0);
		r->data.ops->permanently_unreachable(r->data.instance);
	}
}

static void
std_reach_link_up(struct mblty_reach_data *data)
{
	std_reach_change_state(std_reach_of(data), MBLTY_SR_LINKUP_QUERY, 0);
}

static void
_std_reach_force_check(struct mblty_standard_reach *r)
{
	/* with no link we can't check */
	if (r->state == MBLTY_SR_UNREACHABLE)
		return;

	std_reach_change_state(r, MBLTY_SR_REACHABLE_QUERYING, 0);
}

static void
std_reach_force_check(struct mblty_reach_data *data)
{
	_std_reach_force_check(std_reach_of(data));
}

static struct mblty_reach_data *
mblty_link_reach(struct mblty_reach_data *data)
{
	list_add_tail(&data->entry, &reach_table);
	return data;
}

static void
mblty_unlink_reach(struct mblty_reach_data *data)
{
	list_del(&data->entry);
}

static void
std_reach_destructor(struct mblty_reach_data *data)
{
	struct mblty_standard_reach *r = std_reach_of(data);

	std_reach_check_cancel_pending(r);
	std_reach_change_state(r, MBLTY_SR_UNKNOWN, 0);
	mblty_unlink_reach(data);
	free_object(r);
}

static int
std_reach_is_reachable(struct mblty_reach_data *data)
{
	struct mblty_standard_reach *r = std_reach_of(data);

	return r->state == MBLTY_SR_REACHABLE ||
	       r->state == MBLTY_SR_REACHABLE_QUERYING;
}

static void
std_reach_expired(suptimer_t *tmr, void *arg)
{
	std_reach_change_state((struct mblty_standard_reach *)arg,
			       MBLTY_SR_REACHABLE_QUERYING, 1);
}

struct mblty_reach_data *
mblty_alloc_standard_reach(mblty_os_intf_t *osh, struct in6_addr *target,
			   int isrouter, int periodic)
{
	struct mblty_standard_reach *std;

	std = allocate_object(struct mblty_standard_reach);
	if (std == NULL)
		return NULL;

	std->data.intf = osh;
	std->data.target = target;
	std->data.flags = 0;
	std->data.baseops = &std_reach_data_ops;
	std->data.ops = NULL;
	std->data.instance = NULL;

	if (periodic) {
		std->data.flags |= MBLTY_REACH_PERIODIC;
		timer_init_with(&std->period_timer, "std periodic reach timer",
				std_reach_expired, std);
		std->check_period = DEFAULT_REACH_TIMEOUT * 1000;
	}

	std->state = MBLTY_SR_UNKNOWN;

	std_reach_mark_reachable(std, isrouter);

	return mblty_link_reach(&std->data);
}

void
mblty_retarget_std_reach(mblty_reach_data_t *data, struct in6_addr *target)
{
	data->target = target;
}

void
mblty_release_reach(struct mblty_reach_data *data)
{
	data->baseops->destructor(data);
}

void
mblty_reach_intf_event(mblty_os_intf_t *osh, int ev)
{
	struct mblty_reach_data *iter, *tmp;

	if ((ev != MBLTY_INTF_EV_LINK_UP) && (ev != MBLTY_INTF_EV_LINK_DOWN))
		return;

	list_for_each_entry_safe (iter, tmp, &reach_table, entry) {
		if (iter->intf != osh)
			continue;

		if (ev == MBLTY_INTF_EV_LINK_UP)
			iter->baseops->link_up(iter);
		else
			iter->baseops->link_down(iter);
	}
}

