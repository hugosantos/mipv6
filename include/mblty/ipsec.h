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

#ifndef _MIPV6_IPSEC_H_
#define _MIPV6_IPSEC_H_

#include <mblty/base-defs.h>
#include <mblty/list-support.h>

struct ipsec_policy {
	/* 0 - in, 1 - out */
	int direction;

	/* these addresses must be valid while the policy is registered */
	struct in6_addr *source;
	struct in6_addr *destination;

	uint32_t spi;

	int proto;

	/* 0 for transport, 1 for tunnel in ESP */
	int ipsec_mode;
	/* IPPROTO_ESP, IPPROTO_AH, etc */
	int ipsec_proto;
	/* 0 for required, 1 for optional */
	int ipsec_optional;

	void *owner;
	void (*is_valid)(struct ipsec_policy *);

	/* private stuff */

#define IPSEC_POLS_UNKNOWN	0x0
#define IPSEC_POLS_ASKING	0x1
#define IPSEC_POLS_INSTALLING	0x2
#define IPSEC_POLS_VALID	0x3
	int state;
	uint32_t sequence;
	struct list_entry entry;
};

struct ipsec_bidir_policy {
	struct ipsec_policy in, out;

	void *owner;
	void (*are_valid)(struct ipsec_bidir_policy *);
};

void ipsec_init();

void ipsec_require_policy(struct ipsec_policy *);
void ipsec_release_policy(struct ipsec_policy *);

void ipsec_require_bidir_pol(struct ipsec_bidir_policy *);
void ipsec_release_bidir_pol(struct ipsec_bidir_policy *);

void ipsec_prepare_bidir_pol(struct ipsec_bidir_policy *, struct in6_addr *src,
			     struct in6_addr *dest, uint32_t spi, int proto,
			     int ipsec_mode, int ipsec_proto, int ipsec_opt);

#endif /* _MIPV6_IPSEC_H_ */
