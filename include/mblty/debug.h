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

#ifndef _SUPPORT_PRIV_DEBUG_H_
#define _SUPPORT_PRIV_DEBUG_H_

struct support_debug_conf {
	const char *log_file;
	int log_level;
};

extern struct support_debug_conf *debug_conf;

#define debug_assert(cond, message, ...) \
	if (!(cond)) \
		debug_assert_ext(__FUNCTION__, __FILE__, __LINE__, \
				 message, ## __VA_ARGS__)

void debug_assert_ext(const char *function, const char *file, int line,
		      const char *message, ...);

#define debug_log(level, format, ...) \
	if ((level) <= debug_conf->log_level) \
		debug_logf(level, format, ## __VA_ARGS__)

#define debug_caller(level, format, ...) \
	if ((level) <= debug_conf->log_level) \
		debug_callerf(level, format, ## __VA_ARGS__)

void debug_init_facilities();
void debug_close_facilities();

void debug_logf(int level, const char *format, ...);
void debug_callerf(int level, const char *format, ...);

void debug_dump(void *uc, void *at);

#endif
