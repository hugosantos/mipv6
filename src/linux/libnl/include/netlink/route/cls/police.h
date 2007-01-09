/*
 * netlink/route/cls/police.h	Policer
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Copyright (c) 2003-2005 Thomas Graf <tgraf@suug.ch>
 */

#ifndef NETLINK_CLS_POLICE_H_
#define NETLINK_CLS_POLICE_H_

#include <netlink/netlink.h>
#include <netlink/cache.h>

extern char *	nl_police2str(int, char *, size_t);
extern int	nl_str2police(const char *);

#endif
