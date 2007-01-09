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

#ifndef _MIPV6_PRIV_MIPV6_H_
#define _MIPV6_PRIV_MIPV6_H_

#include <mblty/debug.h>
#include <mblty/ndisc.h>
#include <mblty/base-defs.h>

typedef struct mipv6_conf mipv6_conf_t;

struct mblty_event_ops;

struct mipv6_conf {
	ndisc_conf_t ndisc;
	struct support_debug_conf debug;
	const char *conf_file;
};

#define MIPV6_DEFAULT_LOGLEVEL	4

typedef enum {
	MIPV6_PARAM_T_NONE = 0,
	MIPV6_PARAM_T_INT,
	MIPV6_PARAM_T_BOOLEAN,
	MIPV6_PARAM_T_ONOFF,
	MIPV6_PARAM_T_IDENTIFIER,
	MIPV6_PARAM_T_ADDRESS,
	MIPV6_PARAM_T_PREFIX,
	MIPV6_PARAM_T_DOMAIN,
	MIPV6_PARAM_T_NAI,
} mipv6_param_type_t;

typedef struct mipv6_conf_item mipv6_conf_item_t;
typedef void (*mipv6_conf_item_handler)(mipv6_conf_item_t *, char *[], int);

#define MIPV6_CONF_MAX_PARAMS	8

struct mipv6_conf_item {
	const char *name;
	mipv6_param_type_t params[MIPV6_CONF_MAX_PARAMS];
	mipv6_conf_item_handler handler;
};

void mipv6_init_program(mipv6_conf_t *, struct mblty_event_ops *);
void mipv6_parse_options(int, char *[], mipv6_conf_t *);
void parse_configuration(const char *, mipv6_conf_item_t *items);

#endif /* _MIPV6_PRIV_MIPV6_H_ */
