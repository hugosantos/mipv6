/*
 * netlink/route/classifier.h       Classifiers
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Copyright (c) 2003-2005 Thomas Graf <tgraf@suug.ch>
 */

#ifndef NETLINK_CLASSIFIER_H_
#define NETLINK_CLASSIFIER_H_

#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/route/tc.h>
#include <netlink/utils.h>

extern struct		rtnl_cls *rtnl_cls_alloc(void);
extern void		rtnl_cls_put(struct rtnl_cls *);
extern void		rtnl_cls_free(struct rtnl_cls *);

extern struct nl_cache *rtnl_cls_alloc_cache(struct nl_handle *, int, uint32_t);

/* classifier addition */
extern int		rtnl_cls_add(struct nl_handle *, struct rtnl_cls *,
				     int);
extern struct nl_msg *	rtnl_cls_build_add_request(struct rtnl_cls *, int);

extern struct nl_msg *rtnl_cls_build_change_request(struct rtnl_cls *, int);
extern struct nl_msg *rtnl_cls_build_delete_request(struct rtnl_cls *, int);
extern int  rtnl_cls_delete(struct nl_handle *, struct rtnl_cls *, int);

/* attribute modification */
extern void rtnl_cls_set_ifindex(struct rtnl_cls *, int);
extern void rtnl_cls_set_handle(struct rtnl_cls *, uint32_t);
extern void rtnl_cls_set_parent(struct rtnl_cls *, uint32_t);
extern void rtnl_cls_set_kind(struct rtnl_cls *, const char *);

extern void rtnl_cls_set_prio(struct rtnl_cls *, int);
extern int  rtnl_cls_get_prio(struct rtnl_cls *);

extern void rtnl_cls_set_protocol(struct rtnl_cls *, int);
extern int  rtnl_cls_get_protocol(struct rtnl_cls *);

#endif
