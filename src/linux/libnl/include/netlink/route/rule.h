/*
 * netlink/route/rule.h		Rules
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Copyright (c) 2003-2005 Thomas Graf <tgraf@suug.ch>
 */

#ifndef NETLINK_RULE_H_
#define NETLINK_RULE_H_

#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/addr.h>
#include <netlink/route/route.h>

struct rtnl_rule;

/* General */
extern struct rtnl_rule *	rtnl_rule_alloc(void);
extern void			rtnl_rule_put(struct rtnl_rule *);
extern void			rtnl_rule_free(struct rtnl_rule *);

extern struct nl_cache * rtnl_rule_alloc_cache(struct nl_handle *);
extern struct nl_cache * rtnl_rule_alloc_cache_by_family(struct nl_handle *,
							 int);
extern void rtnl_rule_dump(struct rtnl_rule *, FILE *, struct nl_dump_params *);

extern struct nl_msg * rtnl_rule_build_add_request(struct rtnl_rule *, int);
extern int rtnl_rule_add(struct nl_handle *, struct rtnl_rule *, int);
extern struct nl_msg * rtnl_rule_build_delete_request(struct rtnl_rule *, int);
extern int rtnl_rule_delete(struct nl_handle *, struct rtnl_rule *, int);


/* attribute modification */
extern void		rtnl_rule_set_family(struct rtnl_rule *, int);
extern int		rtnl_rule_get_family(struct rtnl_rule *);
extern void		rtnl_rule_set_prio(struct rtnl_rule *, int);
extern int		rtnl_rule_get_prio(struct rtnl_rule *);
extern void		rtnl_rule_set_fwmark(struct rtnl_rule *, uint64_t);
extern uint64_t		rtnl_rule_get_fwmark(struct rtnl_rule *);
extern void		rtnl_rule_set_table(struct rtnl_rule *, int);
extern int		rtnl_rule_get_table(struct rtnl_rule *);
extern void		rtnl_rule_set_dsfield(struct rtnl_rule *, int);
extern int		rtnl_rule_get_dsfield(struct rtnl_rule *);
extern int		rtnl_rule_set_src(struct rtnl_rule *, struct nl_addr *);
extern struct nl_addr *	rtnl_rule_get_src(struct rtnl_rule *);
extern int		rtnl_rule_set_dst(struct rtnl_rule *, struct nl_addr *);
extern struct nl_addr *	rtnl_rule_get_dst(struct rtnl_rule *);
extern void		rtnl_rule_set_src_len(struct rtnl_rule *, int);
extern int		rtnl_rule_get_src_len(struct rtnl_rule *);
extern void		rtnl_rule_set_dst_len(struct rtnl_rule *, int);
extern int		rtnl_rule_get_dst_len(struct rtnl_rule *);

extern void		rtnl_rule_set_action(struct rtnl_rule *, int);
extern int		rtnl_rule_get_action(struct rtnl_rule *);

extern int		rtnl_rule_set_iif(struct rtnl_rule *, const char *);
extern char *		rtnl_rule_get_iif(struct rtnl_rule *);

extern void		rtnl_rule_set_classid(struct rtnl_rule *, uint32_t);
extern uint32_t		rtnl_rule_get_classid(struct rtnl_rule *);

extern void		rtnl_rule_set_realms(struct rtnl_rule *, realm_t);
extern realm_t		rtnl_rule_get_realms(struct rtnl_rule *);

#endif
