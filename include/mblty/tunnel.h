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

#ifndef _MIPV6_TUNNEL_H_
#define _MIPV6_TUNNEL_H_

#include <netinet/in.h>

struct mblty_os_intf;

typedef struct mblty_tunnel mblty_tunnel_t;
typedef struct mblty_tunnel_ops mblty_tunnel_ops_t;
typedef struct mblty_tunnel_factory mblty_tunnel_factory_t;

struct mblty_tunnel {
	struct mblty_os_intf *osh;
	mblty_tunnel_ops_t *ops;
};

struct mblty_tunnel_ops {
	int (*update)(mblty_tunnel_t *, struct in6_addr *, struct in6_addr *);
	void (*destructor)(mblty_tunnel_t *);
};

struct mblty_tunnel_factory {
	mblty_tunnel_t *(*allocate)(mblty_tunnel_factory_t *,
				    struct in6_addr *, struct in6_addr *);
};

typedef enum {
	MBLTY_TUN_TYPE_IP6IP6 = 1,
} mblty_tunnel_type_t;

mblty_tunnel_factory_t *mblty_obtain_tunnel_factory(mblty_tunnel_type_t);
void mblty_return_tunnel_factory(mblty_tunnel_factory_t *);

mblty_tunnel_t *mblty_tunnel_alloc(mblty_tunnel_factory_t *,
				   struct in6_addr *, struct in6_addr *);
int mblty_tunnel_update(mblty_tunnel_t *, struct in6_addr *,
			struct in6_addr *);
void mblty_tunnel_release(mblty_tunnel_t *);

#endif
