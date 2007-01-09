/*
 * netlink/route/addr.c		rtnetlink addr layer
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Copyright (c) 2003-2005 Thomas Graf <tgraf@suug.ch>
 *                         Baruch Even <baruch@ev-en.org>,
 *                         Mediatrix Telecom, inc. <ericb@mediatrix.com>
 */

#ifndef NETADDR_ADDR_H_
#define NETADDR_ADDR_H_

#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/addr.h>

struct rtnl_addr;
struct nl_msg;

/* General */
extern struct rtnl_addr *rtnl_addr_alloc(void);
extern struct rtnl_addr *rtnl_addr_alloc_from_msg(struct nl_msg *);
extern void		rtnl_addr_put(struct rtnl_addr *);
extern void		rtnl_addr_free(struct rtnl_addr *);

extern struct nl_cache *rtnl_addr_alloc_cache(struct nl_handle *);

/* Address Addition */
extern struct nl_msg *	rtnl_addr_build_add_request(struct rtnl_addr *, int);
extern int		rtnl_addr_add(struct nl_handle *, struct rtnl_addr *,
				      int);

/* Address Deletion */
extern struct nl_msg *	rtnl_addr_build_delete_request(struct rtnl_addr *, int);
extern int		rtnl_addr_delete(struct nl_handle *,
					 struct rtnl_addr *, int);

/* Address Flags Translations */
extern char *		rtnl_addr_flags2str(int, char *, size_t);
extern int		rtnl_addr_str2flags(const char *);

/* Attribute Access */
extern void		rtnl_addr_set_label(struct rtnl_addr *, const char *);
extern char *		rtnl_addr_get_label(struct rtnl_addr *);

extern void		rtnl_addr_set_ifindex(struct rtnl_addr *, int);
extern int		rtnl_addr_get_ifindex(struct rtnl_addr *);

extern void		rtnl_addr_set_family(struct rtnl_addr *, int);
extern int		rtnl_addr_get_family(struct rtnl_addr *);

extern void		rtnl_addr_set_prefixlen(struct rtnl_addr *, int);
extern int		rtnl_addr_get_prefixlen(struct rtnl_addr *);

extern void		rtnl_addr_set_scope(struct rtnl_addr *, int);
extern int		rtnl_addr_get_scope(struct rtnl_addr *);

extern void		rtnl_addr_set_flags(struct rtnl_addr *, unsigned int);
extern void		rtnl_addr_unset_flags(struct rtnl_addr *, unsigned int);
extern unsigned int	rtnl_addr_get_flags(struct rtnl_addr *);

extern int		rtnl_addr_set_local(struct rtnl_addr *,
					    struct nl_addr *);
extern struct nl_addr *	rtnl_addr_get_local(struct rtnl_addr *);

extern int		rtnl_addr_set_peer(struct rtnl_addr *,
					   struct nl_addr *);
extern struct nl_addr *	rtnl_addr_get_peer(struct rtnl_addr *);

extern int		rtnl_addr_set_broadcast(struct rtnl_addr *,
						struct nl_addr *);
extern struct nl_addr *	rtnl_addr_get_broadcast(struct rtnl_addr *);

extern int		rtnl_addr_set_anycast(struct rtnl_addr *,
					      struct nl_addr *);
extern struct nl_addr *	rtnl_addr_get_anycast(struct rtnl_addr *);

extern int		rtnl_addr_set_multicast(struct rtnl_addr *,
						struct nl_addr *);
extern struct nl_addr *	rtnl_addr_get_multicast(struct rtnl_addr *);

#endif