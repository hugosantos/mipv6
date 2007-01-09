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

#ifndef _MIPV6_OS_H_
#define _MIPV6_OS_H_

#include <netinet/in.h>

enum {
	/* local=HoA, remote=CN will add HoA DSTOPT */
	OS_BCE_DIR_LOCAL	= 1,
	/* local=CN remote=HoA will add RTHDR2 */
	OS_BCE_DIR_REMOTE	= 2,
};

int kern_bcache_init();
void kern_bcache_shutdown();

/* function responsible of updating the binding cache. an
 * indirection of NULL will remove the binding cache entry. */
int kern_bcache_update(struct in6_addr *local, struct in6_addr *remote,
		       int direction, struct in6_addr *indirection,
		       void (*cb)(void *), void *argument);
int kern_bcache_get_stat(struct in6_addr *local, struct in6_addr *remote,
			 uint32_t *);
void kern_bcache_clear();

#endif /* _MIPV6_OS_H_ */
