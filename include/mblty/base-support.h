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

#ifndef _SUPPORT_BASE_H_
#define _SUPPORT_BASE_H_

#include <errno.h>
#include <string.h>

#include <mblty/debug.h>
#include <mblty/memory.h>
#include <mblty/timers.h>
#include <mblty/base-defs.h>
#include <mblty/list-support.h>
#include <mblty/heap-support.h>

struct mblty_event_ops;

struct mblty_shutdown_entry {
	void (*handler)();
	struct list_entry entry;
};

void perform_shutdown(const char *fmt, ...);

void mblty_parse_options(int, char *[]);
void mblty_init_program(struct support_debug_conf *, struct mblty_event_ops *);
int mblty_main_loop();
void mblty_register_shutdown(struct mblty_shutdown_entry *);
void mblty_shutdown();

void mblty_copyright_header();

void os_internal_init();
void os_internal_shutdown();

#endif /* _SUPPORT_BASE_H_ */
