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

#ifndef _MIPV6_PROTO_DEFS_H_
#define _MIPV6_PROTO_DEFS_H_

#include <mblty/base-support.h>

struct ip6_mh;
struct ip6_mh_opt;
struct ip6_mh_home_test;
struct ip6_mh_binding_ack;
struct ip6_mh_careof_test;
struct ip6_mh_home_test_init;
struct ip6_mh_binding_update;
struct ip6_mh_careof_test_init;

typedef struct mipv6_msgctx mipv6_msgctx_t;
typedef struct mipv6_auth_data mipv6_auth_data_t;
typedef struct mipv6_mh_bld_ctx mipv6_mh_bld_ctx_t;
typedef struct mipv6_bcache_entry mipv6_bcache_entry_t;
typedef struct mipv6_auth_data_ops mipv6_auth_data_ops_t;
typedef struct mipv6_binding_context mipv6_binding_context_t;
typedef struct mipv6_binding_msg_auth mipv6_binding_msg_auth_t;

typedef struct mipv6_responder_auth mipv6_responder_auth_t;
typedef struct mipv6_responder_auth_ops mipv6_responder_auth_ops_t;
typedef struct mipv6_responder_auth_data mipv6_responder_auth_data_t;
typedef struct mipv6_responder_auth_data_ops mipv6_responder_auth_data_ops_t;

#endif
