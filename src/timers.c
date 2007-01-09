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

#include <string.h>
#include <unistd.h> /* for _SC_CLK_TCK */
#include <sys/times.h> /* for times() */

#include <mblty/base-support.h>

#define DEBUG_TIMERS		0

#define IMPOSSIBLE_FUTURE	(~0ULL)

static struct heap timers;

void
timer_init(suptimer_t *tmr, const char *name)
{
	strncpy(tmr->name, name, SUPPORT_TIMER_MAXNAME);
	tmr->name[SUPPORT_TIMER_MAXNAME] = 0;

	tmr->target = IMPOSSIBLE_FUTURE;
	tmr->cb = NULL;
	tmr->cb_arg = NULL;
}

void
timer_init_with(suptimer_t *tmr, const char *name, sup_timer_callback cb,
		void *arg)
{
	timer_init(tmr, name);
	tmr->cb = cb;
	tmr->cb_arg = arg;
}

static inline void
timer_expired(suptimer_t *tmr)
{
#if DEBUG_TIMERS
	debug_log(10, "timer_expired(%s)\n", tmr->name);
#endif

	debug_assert(tmr->cb, "timer \"%s\" tmr->cb is NULL\n", tmr->name);

	tmr->cb(tmr, tmr->cb_arg);
}

static inline suptimer_t *
timer_from(struct heap_item *i)
{
	return container_of(i, suptimer_t, item);
}

static inline suptimer_t *
timers_top()
{
	return timer_from(heap_top(&timers));
}

void
support_handle_timers()
{
	uint64_t now = support_get_sys_timestamp();
	suptimer_t *tmr;

	while (!heap_empty(&timers)) {
		tmr = timers_top();

		if (tmr->target > now)
			break;

		heap_pop(&timers);
		tmr->target = IMPOSSIBLE_FUTURE;
		timer_expired(tmr);
	}
}

int
support_time_left()
{
	suptimer_t *tmr;
	uint64_t now;

	if (heap_empty(&timers))
		return -1;

	tmr = timers_top();
	now = support_get_sys_timestamp();

	if (now > tmr->target)
		return 0;

	return tmr->target - now;
}

static void
timer_fill_target(suptimer_t *tmr, int increment)
{
	tmr->target = support_get_sys_timestamp() + increment;
	tmr->interval = increment;
}

void
timer_add_debug(const char *function, const char *file, int line,
		suptimer_t *tmr, int increment)
{
	debug_assert(tmr->target == IMPOSSIBLE_FUTURE,
		     "Adding already running timer (%s) at %s in %s:%i.",
		     tmr->name, function, file, line);

	timer_fill_target(tmr, increment);

#if DEBUG_TIMERS
	debug_log(10, "add_timer(%s, %i)\n", tmr->name, increment);
#endif

	heap_push(&timers, &tmr->item);
}

void
timer_remove_debug(const char *function, const char *file, int line,
		   suptimer_t *tmr)
{
	debug_assert(tmr->target != IMPOSSIBLE_FUTURE,
		     "Stopping timer (%s) which is not running at %s in %s:%i.",
		     tmr->name, function, file, line);

#if DEBUG_TIMERS
	debug_log(10, "remove_timer(%s)\n", tmr->name);
#endif

	heap_remove(&timers, &tmr->item);

	tmr->target = IMPOSSIBLE_FUTURE;
}

uint64_t
timer_remaining_time(suptimer_t *tmr)
{
	return tmr->target - support_get_sys_timestamp();
}

void
timer_update(suptimer_t *tmr, int increment)
{
	timer_fill_target(tmr, increment);

	heap_update(&timers, &tmr->item);
}

struct timer_iter_data {
	void (*cb)(suptimer_t *, void *);
	void *argument;
};

static void
for_one_timer(struct heap_item *item, void *argument)
{
	suptimer_t *tmr = timer_from(item);
	struct timer_iter_data *data = argument;

	data->cb(tmr, data->argument);
}

void
support_foreach_timer(void (*cb)(suptimer_t *, void *), void *arg)
{
	struct timer_iter_data t;

	t.cb = cb;
	t.argument = arg;

	heap_foreach_item(&timers, for_one_timer, &t);
}

uint64_t
support_get_sys_timestamp()
{
	uint64_t result;
	struct tms tms;

	/* result is in ticks */
	result = times(&tms);

	result *= 1000;
	result /= sysconf(_SC_CLK_TCK);

	return result;
}

static int
compare_timers(struct heap *h, struct heap_item *_a, struct heap_item *_b)
{
	suptimer_t *a, *b;

	a = timer_from(_a);
	b = timer_from(_b);

	if (a->target > b->target)
		return 1;
	else if (a->target < b->target)
		return -1;
	return 0;
}

void
support_timers_init()
{
	heap_init(&timers);
	timers.compare = compare_timers;
}

void
support_timers_shutdown()
{
	heap_free(&timers);
}

