/*
 * netlink/route/qdisc-modules.h       Qdisc Module API
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Copyright (c) 2003-2005 Thomas Graf <tgraf@suug.ch>
 */

#ifndef NETLINK_QDISC_MODULES_H_
#define NETLINK_QDISC_MODULES_H_

#include <netlink/netlink.h>

/**
 * Qdisc Operations
 * @ingroup qdisc
 */
struct rtnl_qdisc_ops
{
	/**
	 * Kind/Name of Qdisc
	 */
	char qo_kind[32];

	/**
	 * Dump callbacks
	 */
	int  (*qo_dump[NL_DUMP_MAX+1])(struct rtnl_qdisc *,
				       struct nl_dump_params *, int);

	/**
	 * Must return the contents supposed to be in TCA_OPTIONS
	 */
	struct nl_msg *(*qo_get_opts)(struct rtnl_qdisc *);

	/**
	 * TCA_OPTIONS message parser
	 */
	int  (*qo_msg_parser)(struct rtnl_qdisc *);

	/**
	 * Called before a Qdisc object gets destroyed
	 */
	void (*qo_free_data)(struct rtnl_qdisc *);

	/**
	 * INTERNAL (Do not use)
	 */
	struct rtnl_qdisc_ops *qo_next;
};

extern int rtnl_qdisc_register(struct rtnl_qdisc_ops *);
extern int rtnl_qdisc_unregister(struct rtnl_qdisc_ops *);

#endif
