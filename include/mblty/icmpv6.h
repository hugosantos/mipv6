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

#ifndef _MIPV6_PRIV_ICMPV6_H_
#define _MIPV6_PRIV_ICMPV6_H_

#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>

#include <mblty/sock-support.h>

struct ip6_hdr;
struct mblty_os_intf;

typedef struct icmpv6_rate_limit icmpv6_rate_limit_t;

struct icmpv6_rate_limit {
	uint32_t n, b;
	uint32_t last, count, now;
};

typedef void (*icmpv6_handler)(struct icmp6_hdr *, int length,
			       supsocket_rxparm_t *);

icmpv6_handler icmpv6_register_handler(int type, icmpv6_handler, int on);

int icmpv6_join_mc(struct mblty_os_intf *, struct in6_addr *);
int icmpv6_leave_mc(struct mblty_os_intf *, struct in6_addr *);

int icmpv6_sk_enable(supsocket_cap_t);
int icmpv6_sk_disable(supsocket_cap_t);

int icmpv6_send(struct in6_addr *to, struct in6_addr *from,
		struct mblty_os_intf *intf, int hoplimit,
		struct icmp6_hdr *, int length);
int icmpv6_send_error(struct in6_addr *to, struct in6_addr *from,
		      struct mblty_os_intf *intf, int hoplimit,
		      struct icmp6_hdr *, int length);

void icmpv6_send_param_prob(int type, int ptr, struct in6_addr *from,
			    struct in6_addr *to, struct ip6_hdr *, int origlen,
			    void *payload, int payloadlen);

void icmpv6_rate_limit_init(icmpv6_rate_limit_t *, uint32_t n, uint32_t b);
int icmpv6_rate_limited(icmpv6_rate_limit_t *);
void icmpv6_rate_limit_add(icmpv6_rate_limit_t *);

void icmpv6_protocol_init();

#endif /* _MIPV6_PRIV_ICMPV6_H_ */
