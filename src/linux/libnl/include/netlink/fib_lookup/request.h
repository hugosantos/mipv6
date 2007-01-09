/*
 * netlink/fib_lookup/request.h		FIB Lookup Request	
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Copyright (c) 2003-2005 Thomas Graf <tgraf@suug.ch>
 */

#ifndef NETLINK_FIB_LOOKUP_REQUEST_H_
#define NETLINK_FIB_LOOKUP_REQUEST_H_

#include <netlink/netlink.h>
#include <netlink/addr.h>

struct flnl_request;

extern struct flnl_request *	flnl_request_alloc(void);

extern struct flnl_request *	flnl_request_get(struct flnl_request *);
extern void			flnl_request_put(struct flnl_request *);
extern void			flnl_request_free(struct flnl_request *);

extern void			flnl_request_set_fwmark(struct flnl_request *,
							uint64_t);
extern uint64_t			flnl_request_get_fwmark(struct flnl_request *);
extern void			flnl_request_set_tos(struct flnl_request *,
						     int);
extern int			flnl_request_get_tos(struct flnl_request *);
extern void			flnl_request_set_scope(struct flnl_request *,
						       int);
extern int			flnl_request_get_scope(struct flnl_request *);
extern void			flnl_request_set_table(struct flnl_request *,
						       int);
extern int			flnl_request_get_table(struct flnl_request *);
extern int			flnl_request_set_addr(struct flnl_request *,
						      struct nl_addr *);
extern struct nl_addr *		flnl_request_get_addr(struct flnl_request *);

extern int			flnl_request_cmp(struct flnl_request *,
						 struct flnl_request *);

#endif
