/*
 * netlink/route/class-modules.h       Class Module API
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Copyright (c) 2003-2005 Thomas Graf <tgraf@suug.ch>
 */

#ifndef NETLINK_CLASS_MODULES_H_
#define NETLINK_CLASS_MODULES_H_

#include <netlink/netlink.h>

/**
 * Class operations
 * @ingroup class
 */
struct rtnl_class_ops
{
	/**
	 * Kind/Name of class
	 */
	char co_kind[32];

	/**
	 * Dump callbacks
	 */
	int (*co_dump[NL_DUMP_MAX+1])(struct rtnl_class *,
				      struct nl_dump_params *, int);

	/**
	 * Must return the contents supposed to be in TCA_OPTIONS
	 */
	struct nl_msg *(*co_get_opts)(struct rtnl_class *);

	/**
	 * TCA_OPTIONS message parser
	 */
	int  (*co_msg_parser)(struct rtnl_class *);

	/**
	 * Called before a class object gets destroyed
	 */
	void (*co_free_data)(struct rtnl_class *);

	/**
	 * INTERNAL (Do not use)
	 */
	struct rtnl_class_ops *co_next;
};

extern int	rtnl_class_register(struct rtnl_class_ops *);
extern int	rtnl_class_unregister(struct rtnl_class_ops *);

#endif
