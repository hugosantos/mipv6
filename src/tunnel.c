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

#include <mblty/tunnel.h>
#include <mblty/base-support.h>

mblty_tunnel_t *
mblty_tunnel_alloc(mblty_tunnel_factory_t *factory, struct in6_addr *local,
		   struct in6_addr *remote)
{
	return factory->allocate(factory, local, remote);
}

int
mblty_tunnel_update(mblty_tunnel_t *tun, struct in6_addr *local,
		    struct in6_addr *remote)
{
	debug_assert(tun && local && remote,
		     "Missing arguments on change_tunnel");

	return tun->ops->update(tun, local, remote);
}

void
mblty_tunnel_release(mblty_tunnel_t *tun)
{
	if (tun == NULL)
		return;

	if (tun->ops->destructor)
		tun->ops->destructor(tun);
	else
		free_object(tun);
}
