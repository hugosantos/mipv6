/*
 * netlink/utils.h		Utility Functions
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Copyright (c) 2003-2005 Thomas Graf <tgraf@suug.ch>
 */

#ifndef NETLINK_UTILS_H_
#define NETLINK_UTILS_H_

#include <netlink/netlink.h>
#include <netlink/list.h>

/**
 * @name Probability Constants
 * @{
 */

/**
 * Lower probability limit
 * @ingroup utils
 */
#define NL_PROB_MIN 0x0

/**
 * Upper probability limit
 * @ingroup utils
 */
#define NL_PROB_MAX 0xffffffff

/** @} */

extern char *	nl_geterror(void);
extern int	nl_get_errno(void);

/* unit pretty-printing */
extern double	nl_cancel_down_bytes(unsigned long long, char **);
extern double	nl_cancel_down_bits(unsigned long long, char **);
extern double	nl_cancel_down_us(uint32_t, char **);

/* generic unit translations */
extern long	nl_size2int(const char *);
extern long	nl_prob2int(const char *);

/* time translations */
extern int	nl_get_hz(void);
extern uint32_t	nl_us2ticks(uint32_t);
extern uint32_t	nl_ticks2us(uint32_t);
extern char *	nl_msec2str(uint64_t, char *, size_t);

/* link layer protocol translations */
extern char *	nl_llproto2str(int, char *, size_t);
extern int	nl_str2llproto(const char *);

/* ethernet protocol translations */
extern char *	nl_ether_proto2str(int, char *, size_t);
extern int	nl_str2ether_proto(const char *);


#endif
