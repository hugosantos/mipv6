/*
 * netlink/fib_lookup/fib_lookup.h	FIB Lookup
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Copyright (c) 2003-2005 Thomas Graf <tgraf@suug.ch>
 */

#ifndef NETLINK_FIB_LOOKUP_H_
#define NETLINK_FIB_LOOKUP_H_

#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/addr.h>
#include <netlink/fib_lookup/request.h>

struct flnl_result;

extern struct flnl_result *	flnl_result_alloc(void);
extern struct nl_cache *	flnl_result_alloc_cache(void);
extern void			flnl_result_put(struct flnl_result *);
extern void			flnl_result_free(struct flnl_result *);

extern struct nl_msg *		flnl_lookup_build_request(struct flnl_request *,
							  int);
extern int			flnl_lookup(struct nl_handle *,
					    struct flnl_request *,
					    struct nl_cache *);

#endif
