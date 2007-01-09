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

#include <mblty/interface.h>
#include <mblty/sock-support.h>

void
mblty_os_intf_get_addresses(mblty_os_intf_t *osh, void (*cb)(mblty_os_intf_t *,
			    struct in6_prefix *, void *), void *param)
{
}

mblty_os_intf_t *
mblty_os_intf_get_by_name(const char *name)
{
	return NULL;
}

void
mblty_os_intf_remove_kernel_addresses(mblty_os_intf_t *osh)
{
}

void
mblty_os_intf_remove_kernel_routes(mblty_os_intf_t *osh)
{
}

int
os_create_socket(supsocket_t *sock, int domain, int type, int proto)
{
	return -1;
}

int
os_close_socket(supsocket_t *sock)
{
	return -1;
}

void
os_internal_init()
{
}

void
os_internal_shutdown()
{
}

