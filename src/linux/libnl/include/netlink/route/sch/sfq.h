/*
 * netlink/route/sch/sfq.c	SFQ Qdisc
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Copyright (c) 2003-2005 Thomas Graf <tgraf@suug.ch>
 */

#ifndef NETLINK_SFQ_H_
#define NETLINK_SFQ_H_

#include <netlink/netlink.h>

extern int	rtnl_sfq_set_quantum(struct rtnl_qdisc *, int);
extern int	rtnl_sfq_get_quantum(struct rtnl_qdisc *);

extern int	rtnl_sfq_set_limit(struct rtnl_qdisc *, int);
extern int	rtnl_sfq_get_limit(struct rtnl_qdisc *);

extern int	rtnl_sfq_set_perturb(struct rtnl_qdisc *, int);
extern int	rtnl_sfq_get_perturb(struct rtnl_qdisc *);

extern int	rtnl_sfq_get_divisor(struct rtnl_qdisc *);

#endif
