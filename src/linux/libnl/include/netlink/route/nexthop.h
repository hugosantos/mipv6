/*
 * netlink/route/nexthop.h	Routing Nexthop
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Copyright (c) 2003-2005 Thomas Graf <tgraf@suug.ch>
 */

#ifndef NETLINK_ROUTE_NEXTHOP_H_
#define NETLINK_ROUTE_NEXTHOP_H_

#include <netlink/netlink.h>
#include <netlink/addr.h>

struct rtnl_nexthop;

extern struct rtnl_nexthop *	rtnl_route_nh_alloc(void);
extern void		rtnl_route_nh_free(struct rtnl_nexthop *);
extern void		rtnl_route_nh_set_weight(struct rtnl_nexthop *, int);
extern void		rtnl_route_nh_set_ifindex(struct rtnl_nexthop *, int);
extern void		rtnl_route_nh_set_gateway(struct rtnl_nexthop *,
						  struct nl_addr *);
extern void		rtnl_route_nh_set_flags(struct rtnl_nexthop *,
						unsigned int);
extern void		rtnl_route_nh_unset_flags(struct rtnl_nexthop *,
						  unsigned int);
extern unsigned int	rtnl_route_nh_get_flags(struct rtnl_nexthop *);

#endif
