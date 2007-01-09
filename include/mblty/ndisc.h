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

#ifndef _MBLTY_NDISC_H_
#define _MBLTY_NDISC_H_

#include <netinet/in.h>

#include <mblty/base-defs.h>
#include <mblty/list-support.h>

struct icmp6_hdr;
struct nd_neighbor_advert;

struct ndisc_ns_conf {
	int count, interval;
};

struct ndisc_conf {
	struct ndisc_ns_conf ns;
	struct ndisc_ns_conf dad;
	struct ndisc_ns_conf nud;
};

#define NDISC_DEFAULT_CONF { \
	.ns = { 5, 1000 }, \
	.dad = { 1, 1000 }, \
	.nud = { 2, 500 }, \
}

struct ndisc_address_ops {
	void (*claimed)(ndisc_address_record_t *);
	void (*dad_failed)(ndisc_address_record_t *);
};

struct ndisc_address_record {
	mblty_address_t *address;
	mblty_interface_t *intf;

	ndisc_address_ops_t *ops;

	/* this state requires DAD */
#define NDISC_ADDRREC_F_NEEDS_DAD	0x00000001
	/* this state is ready to reply and generate messags */
#define NDISC_ADDRREC_F_READY		0x00000002
	/* after address is claimed, send an unsolicited neigh adv */
#define NDISC_ADDRREC_F_NOISY		0x00000004
	/* joined the solicited address mc address - internal use */
#define NDISC_ADDRREC_F_JOINEDSOL	0x10000000
#define NDISC_ADDRREC_F_PENDING_DAD	0x20000000
	uint32_t flags;

	struct list_entry entry;
};

struct ndisc_handler_context {
	mblty_os_intf_t *iif;
	struct in6_addr *source, *dest;

	union {
		uint8_t *raw;
		struct icmp6_hdr *icmp6;
		struct nd_router_solicit *rtsol;
		struct nd_router_advert *rtadv;
		struct nd_neighbor_solicit *neisol;
		struct nd_neighbor_advert *neiadv;
		struct nd_redirect *redir;
	} hdr;

	union {
		uint8_t *raw;
		struct nd_opt_hdr *hdr;
		struct nd_opt_prefix_info *pi;
		struct nd_opt_rd_hdr *rd;
		struct nd_opt_mtu *mtu;
		struct nd_opt_adv_interval *advint;
		struct nd_opt_home_agent_info *hainfo;
	} opt;

	int length, optlen;

	uint8_t *next_opt;
};

struct ndisc_handler {
	void (*event)(ndisc_handler_context_t *);
	struct list_entry entry;
};

int ndisc_register_handler(int type, ndisc_handler_t *);
int ndisc_unregister_handler(int type, ndisc_handler_t *);

/* returns < 0 on error, 0 on no more options, > 0 on success */
int ndisc_handctx_next_opt(ndisc_handler_context_t *);
/* returns < 0 on error, 0 on success */
int ndisc_handctx_check_opts(ndisc_handler_context_t *);

int ndisc_addr_register(ndisc_address_record_t *, mblty_interface_t *,
			mblty_address_t *, ndisc_address_ops_t *);
void ndisc_addr_proceed(ndisc_address_record_t *);
void ndisc_addr_reset(ndisc_address_record_t *);
void ndisc_addr_unregister(ndisc_address_record_t *);

struct ndisc_nud_result {
	enum {
		NDISC_NUD_RES_REACHABLE,
		NDISC_NUD_RES_FAILED,
		NDISC_NUD_RES_EXPIRED,
	} result;

	uint32_t flags;
	struct nd_opt_hdr *linkaddr_opt;
};

typedef void (*ndisc_nud_reply_cb_t)(ndisc_nud_result_t *, void *param);

void ndisc_perform_nud(mblty_os_intf_t *, struct in6_addr *target,
		       ndisc_nud_reply_cb_t cb, void *param);
void ndisc_cancel_nud(ndisc_nud_reply_cb_t cb, void *param);

enum {
	MBLTY_NEIGH_SOLICIT_OK = 0,
	MBLTY_NEIGH_SOLICIT_FAILED = -1,
	MBLTY_NEIGH_SOLICIT_EXPIRED = 2,
};

typedef void (*ndisc_solicitation_cb_t)(ndisc_handler_context_t *, int result,
				        void *argument);

/* argument also acts as cookie */
void ndisc_do_neigh_solicit(mblty_os_intf_t *, struct in6_addr *target,
			    ndisc_solicitation_cb_t cb, void *argument);
void ndisc_cancel_neigh_solicit(void *argument);

#define MBLTY_NEIGH_MAX_LLADDR_SIZE	22
#define MBLTY_NEIGH_LLADDR_OPT_MAXSIZE	(MBLTY_NEIGH_MAX_LLADDR_SIZE + 2)

/* ptr must point to a buffer of at least (lladdr_size+2)
 * octets (or MBLTY_NEIGH_LLADDR_OPT_MAXSIZE to be safe) */
int ndisc_prepare_lladdr_opt(int type, uint8_t *, int len, mblty_os_intf_t *);

void ndisc_init(ndisc_conf_t *);

#endif
