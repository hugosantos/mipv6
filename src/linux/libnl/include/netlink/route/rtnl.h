/*
 * netlink/route/rtnl.h		Routing Netlink
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Copyright (c) 2003-2005 Thomas Graf <tgraf@suug.ch>
 */

#ifndef NETLINK_RTNL_H_
#define NETLINK_RTNL_H_

#include <netlink/netlink.h>

/**
 * @name Realms
 * @{
 */

typedef uint32_t	realm_t;

/**
 * Mask specying the size of each realm part
 * @ingroup rtnl
 */
#define RTNL_REALM_MASK (0xFFFF)

/**
 * Extract FROM realm from a realms field
 */
#define RTNL_REALM_FROM(realm) ((realm) >> 16)

/**
 * Extract TO realm from a realms field
 */
#define RTNL_REALM_TO(realm) ((realm) & RTNL_REALM_MASK)

/**
 * Build a realms field
 */
#define RTNL_MAKE_REALM(from, to) \
	((RTNL_REALM_TO(from) << 16) & RTNL_REALM_TO(to))

/** @} */


/* General */
extern int		nl_rtgen_request(struct nl_handle *, int, int, int);

/* Routing Type Translations */
extern char *		nl_rtntype2str(int, char *, size_t);
extern int		nl_str2rtntype(const char *);

/* Scope Translations */
extern char *		rtnl_scope2str(int, char *, size_t);
extern int		rtnl_str2scope(const char *);

/* Realms Translations */
extern char *		rtnl_realms2str(uint32_t, char *, size_t);

#endif
