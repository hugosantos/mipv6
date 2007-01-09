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

#ifndef _PRIV_TIMERS_H_
#define _PRIV_TIMERS_H_

#include <stdint.h>
#include <mblty/heap-support.h>

struct sup_timer;

typedef void (*sup_timer_callback)(struct sup_timer *, void *);

typedef struct sup_timer {
#define SUPPORT_TIMER_MAXNAME	31
	char name[SUPPORT_TIMER_MAXNAME + 1];

	uint64_t target;
	int interval;

	sup_timer_callback cb;
	void *cb_arg;

	struct heap_item item;
} suptimer_t;

void support_handle_timers();
int support_time_left();
void support_foreach_timer(void (*)(suptimer_t *, void *), void *);
/* returns system absolute time in miliseconds */
uint64_t support_get_sys_timestamp();

void support_timers_init();
void support_timers_shutdown();

void timer_init(suptimer_t *, const char *name);
void timer_init_with(suptimer_t *, const char *, sup_timer_callback, void *);

void timer_add_debug(const char *fun, const char *file, int l, suptimer_t *, int inc);
void timer_remove_debug(const char *fun, const char *file, int l, suptimer_t *);
void timer_update(suptimer_t *, int increment);

#define timer_add(tmr, inc) \
	timer_add_debug(__FUNCTION__, __FILE__, __LINE__, tmr, inc)

#define timer_remove(tmr) \
	timer_remove_debug(__FUNCTION__, __FILE__, __LINE__, tmr)

uint64_t timer_remaining_time(suptimer_t *);

#endif /* _PRIV_TIMERS_H_ */
