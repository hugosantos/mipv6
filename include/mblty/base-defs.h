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

#ifndef _MIPV6_BASE_DEFS_H_
#define _MIPV6_BASE_DEFS_H_

#include <netinet/in.h> /* for struct in6_addr */
#include <string.h> /* for memcpy() */

/* address */
typedef struct mblty_prefix mblty_prefix_t;
typedef struct mblty_address mblty_address_t;
typedef struct mblty_link_addr mblty_link_addr_t;
typedef struct mblty_intf_addr mblty_intf_addr_t;
typedef struct mblty_link_local mblty_link_local_t;
typedef struct mblty_intf_prefix mblty_intf_prefix_t;
typedef struct mblty_base_address mblty_base_address_t;
typedef struct mblty_managed_addr mblty_managed_addr_t;
typedef struct mblty_intf_addr_ops mblty_intf_addr_ops_t;
typedef struct mblty_addr_category mblty_addr_category_t;
typedef struct mblty_router_prefix mblty_router_prefix_t;
typedef struct mblty_managed_address mblty_managed_address_t;
typedef struct mblty_network_address mblty_network_address_t;
typedef struct mblty_unicast_address mblty_unicast_address_t;
typedef struct mblty_managed_interest mblty_managed_interest_t;
typedef struct mblty_network_address_ops mblty_network_address_ops_t;
typedef struct mblty_managed_interest_ops mblty_managed_interest_ops_t;

/* interface */
typedef struct mblty_eui64 mblty_eui64_t;
typedef struct mblty_os_intf mblty_os_intf_t;
typedef struct mblty_interface mblty_interface_t;
typedef struct mblty_os_intf_ops mblty_os_intf_ops_t;

/* ndisc */
typedef struct ndisc_conf ndisc_conf_t;
typedef struct ndisc_handler ndisc_handler_t;
typedef struct ndisc_nud_result ndisc_nud_result_t;
typedef struct ndisc_address_ops ndisc_address_ops_t;
typedef struct ndisc_address_record ndisc_address_record_t;
typedef struct ndisc_handler_context ndisc_handler_context_t;

/* reach */
typedef struct mblty_reach_data mblty_reach_data_t;
typedef struct mblty_standard_reach mblty_standard_reach_t;
typedef struct mblty_reach_data_ops mblty_reach_data_ops_t;
typedef struct mblty_reachability_ops mblty_reachability_ops_t;

/* router */
typedef struct mblty_router mblty_router_t;
typedef struct mblty_router_ops mblty_router_ops_t;
typedef struct mblty_router_name mblty_router_name_t;

struct in6_prefix {
	struct in6_addr address;
	int prefixlen;
};

#define INET6_PREFIXSTRLEN (INET6_ADDRSTRLEN + 1 + 3)

/* returns zero if the address matches the prefix */
int in6_prefix_matches(struct in6_prefix *, struct in6_addr *);
void in6_prefix_apply(struct in6_prefix *);

/* helper functions */
static inline struct in6_addr *
in6_addr_copy(struct in6_addr *dest, const struct in6_addr *src)
{
	memcpy(dest, src, sizeof(struct in6_addr));
	return dest;
}

static inline int
in6_addr_compare(const struct in6_addr *a1, const struct in6_addr *a2)
{
	return memcmp(a1, a2, sizeof(struct in6_addr));
}

static inline struct in6_prefix *
in6_prefix_copy(struct in6_prefix *dest, const struct in6_prefix *src)
{
	in6_addr_copy(&dest->address, &src->address);
	dest->prefixlen = src->prefixlen;
	return dest;
}

static inline struct in6_prefix *
in6_prefix_copy_applied(struct in6_prefix *dest, const struct in6_prefix *src)
{
	in6_prefix_copy(dest, src);
	in6_prefix_apply(dest);
	return dest;
}

static inline int
in6_prefix_compare(struct in6_prefix *p1, struct in6_prefix *p2)
{
	if (p1->prefixlen < p2->prefixlen)
		return -1;
	else if (p1->prefixlen > p2->prefixlen)
		return 1;
	return in6_addr_compare(&p1->address, &p2->address);
}

/* buffer MUST be at least INET6_ADDRSTRLEN chars length */
const char *format_addr(char *buffer, const struct in6_addr *);
/* buffer MUST be at least INET6_PREFIXSTRLEN chars length */
const char *format_prefix(char *buffer, const struct in6_prefix *);

#endif
