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

#ifndef _MN_HELPER_H_
#define _MN_HELPER_H_

#include <netinet/in.h> /* for in6_addr */

enum {
	MN_H_CMD_ADDINTF	= 1,
	MN_H_CMD_RO,
};

struct mipv6_mn_helper_cmd {
	int command, type;
	union {
		char intfname[IFNAMSIZ];
		int value;
		struct {
			struct in6_addr local, remote;
		} ro;
	} u;
};

#endif
