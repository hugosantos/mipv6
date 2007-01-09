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

#include <stdio.h>
#include <arpa/inet.h>

#include <mblty/base-support.h>

const char *
format_addr(char *buffer, const struct in6_addr *addr)
{
	if (addr == NULL)
		return strcpy(buffer, "(NULL)");
	return inet_ntop(AF_INET6, addr, buffer, INET6_ADDRSTRLEN);
}

/* buffer MUST be at least INET6_PREFIXSTRLEN chars length */
const char *
format_prefix(char *buffer, const struct in6_prefix *pfx)
{
	const char *p;

	if (pfx == NULL)
		return strcpy(buffer, "(NULL)");

	p = format_addr(buffer, &pfx->address);

	if (pfx->prefixlen < 128)
		sprintf(buffer + strlen(p), "/%i", pfx->prefixlen);

	return p;
}

int
in6_prefix_matches(struct in6_prefix *prefix, struct in6_addr *addr)
{
	uint32_t mask, *a1, *a2;
	int plen;

	if (prefix->prefixlen == 128)
		return in6_addr_compare(&prefix->address, addr);

	a1 = (uint32_t *)(&prefix->address);
	a2 = (uint32_t *)(addr);

	for (plen = prefix->prefixlen; plen >= 32; plen -= 32) {
		if (*a1 != *a2)
			return -1;
		a1++;
		a2++;
	}

	if (plen) {
		mask = 0xffffffff << (32 - plen);

		if ((*a1 & mask) != (*a2 & mask))
			return -1;
	}

	return 0;
}

void
in6_prefix_apply(struct in6_prefix *prefix)
{
	int off = prefix->prefixlen / 8;

	if (prefix->prefixlen & 7) {
		int mask = 0xff << (8 - (prefix->prefixlen & 7));
		prefix->address.s6_addr[off] &= mask;
		off++;
	}

	memset(prefix->address.s6_addr + off, 0, 16 - off);
}

