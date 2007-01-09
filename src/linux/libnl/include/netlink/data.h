/*
 * netlink/data.h	Abstract Data
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Copyright (c) 2003-2005 Thomas Graf <tgraf@suug.ch>
 */

#ifndef NETLINK_DATA_H_
#define NETLINK_DATA_H_

#include <netlink/netlink.h>

struct nl_data;

/* General */
extern struct nl_data *	nl_data_alloc(void *, size_t);
extern int		nl_data_append(struct nl_data *, void *, size_t);
extern void		nl_data_free(struct nl_data *);

/* Access Functions */
extern void *		nl_data_get(struct nl_data *);
extern size_t		nl_data_get_size(struct nl_data *);

/* Misc */
extern int		nl_data_cmp(struct nl_data *, struct nl_data *);

#endif
