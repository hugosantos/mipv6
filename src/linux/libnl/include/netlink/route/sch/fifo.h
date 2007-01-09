/*
 * netlink/route/sch/fifo.c	FIFO Qdisc
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Copyright (c) 2003-2005 Thomas Graf <tgraf@suug.ch>
 */

#ifndef NETLINK_FIFO_H_
#define NETLINK_FIFO_H_

#include <netlink/netlink.h>

extern int	rtnl_qdisc_fifo_set_limit(struct rtnl_qdisc *, int);
extern int	rtnl_qdisc_fifo_get_limit(struct rtnl_qdisc *);

#endif
