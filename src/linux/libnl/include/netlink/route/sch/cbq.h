/*
 * netlink/route/sch/cbq.h	Class Based Queueing
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Copyright (c) 2003-2005 Thomas Graf <tgraf@suug.ch>
 */

#ifndef NETLINK_CBQ_H_
#define NETLINK_CBQ_H_

#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/route/qdisc.h>

extern char * nl_ovl_strategy2str(int, char *, size_t);
extern int    nl_str2ovl_strategy(const char *);

#endif
