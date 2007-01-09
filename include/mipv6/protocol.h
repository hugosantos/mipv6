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

#ifndef _MIPV6_PRIV_PROTOCOL_H_
#define _MIPV6_PRIV_PROTOCOL_H_

#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/ip6mh.h>

#include <mblty/timers.h>
#include <mblty/address.h>
#include <mblty/interface.h>
#include <mblty/list-support.h>

#include <mipv6/proto-defs.h>

struct mipv6_msg_stat_rx {
	uint32_t rx, dscrd;
};

struct mipv6_msg_stat_tx {
	uint32_t tx, failed;
};

struct mipv6_msg_stats {
	/* transmitted messages: BU, HOTI, COTI */
	struct mipv6_msg_stat_tx bu, hoti, coti;
	/* received messages: BACK, BRR, BERR, HOT, COT */
	struct mipv6_msg_stat_rx back, brr, berr, hot, cot;
};

typedef enum {
	MIPV6_BCTX_ERRLVL_INTERNAL = 0,
	MIPV6_BCTX_ERRLVL_BERR,
	MIPV6_BCTX_ERRLVL_BACK,
} mipv6_binding_ctx_errlevel;

struct mipv6_binding_context {
	mipv6_binding_context_t *parent;

	mblty_network_address_t *hoa;
	struct in6_addr *destination;
	uint16_t sequence;
	int lifetime, active_lifetime;
	int refresh_advice;

	void *owner;

#define MIPV6_BCTX_SCHEDULED_BU	0x0001
/* the binding updates should be ACKed */
#define MIPV6_BCTX_WANT_ACK	0x0002
/* this is a home registration */
#define MIPV6_BCTX_HOMEREG	0x0004
/* we are currently waiting for ACK, retrasmission timer is on */
#define MIPV6_BCTX_WAITING_ACK	0x0008
/* our binding is active */
#define MIPV6_BCTX_ACTIVE_REG	0x0010
/* no BUs should be sent */
#define MIPV6_BCTX_NO_SEND_BU	0x0020
/* use alternate CoA mobopt */
#define MIPV6_BCTX_USE_ALT_COA	0x0040
/* the binding failed */
#define MIPV6_BCTX_FAILED	0x0100
/* the send of a BU is pending */
#define MIPV6_BCTX_HAS_NAI	0x0400
#define MIPV6_BCTX_EXPIRED	0x0800
#define MIPV6_BCTX_PENDING_NEW_REG	0x1000
	uint32_t flags;

	mblty_address_t *coa;

	uint64_t ts_bu_last_sent;
	suptimer_t valid, trans;

	uint32_t retry_timeout;
	mipv6_bcache_entry_t *reverse;

	struct {
		mipv6_binding_ctx_errlevel level;
		int status;
	} error;

	struct mipv6_msg_stats stats;

	/* callbacks */
	void (*cb_update_failed)(mipv6_binding_context_t *);
	void (*cb_completed_reg)(mipv6_binding_context_t *);

	mipv6_auth_data_t *auth;
	char *nai;

	struct list_entry entry;
};

enum {
	MIPV6_BCTX_ERROR_NOSUPP = 1,
};

/* binding cache entry */
struct mipv6_bcache_entry {
	struct in6_addr local, hoa, coa, active_coa;
	uint16_t lifetime;
	uint16_t sequence;
#define MIPV6_BCE_VALID		0x0001
#define MIPV6_BCE_PENDING_UPD	0x0002
#define MIPV6_BCE_WANTS_ACK	0x0004
#define MIPV6_BCE_HOME_REG	0x0008
	uint32_t flags;

	mipv6_binding_context_t *reverse;
	mipv6_responder_auth_data_t *pending_auth;

	void (*cb_destructor)(mipv6_bcache_entry_t *);
	void (*cb_entry_expired)(mipv6_bcache_entry_t *);

	suptimer_t lifetime_timer;

	struct list_entry entry;
};

/* binding update lifetime is counted in 4-sec units */
#define MIPV6_BU_LIFETIME(x)		(((x) + 3) / 4)
#define MIPV6_GET_BU_LIFETIME(x)	((int)(x) * 4)

struct mipv6_msgctx {
	struct in6_addr *hoa, *from, *to;
	/* If the packet included a RT2 HDR, origdst will
	 * point to the original destination (CoA) */
	struct in6_addr *origdst;
	mblty_os_intf_t *intf;

	union {
		void *raw;
		struct ip6_mh *hdr;
	} u;

	size_t msglen;

	struct ip6_hdr *orighdr;
	size_t orighdrlen;
};

struct mipv6_proto_ops {
	int (*authorize_binding)(
		mipv6_responder_auth_data_t **, mipv6_bcache_entry_t *,
		struct in6_addr *, struct in6_addr *, mipv6_msgctx_t *);
	mipv6_bcache_entry_t *(*create_bcache_entry)(mipv6_msgctx_t *);
	void (*post_create_bcache_entry)(mipv6_bcache_entry_t *);
	void (*binding_changed)(mipv6_bcache_entry_t *, int wasvalid);
	void (*bcache_miss)(struct in6_addr *, struct in6_addr *);
};

extern struct mipv6_proto_ops mipv6_proto_ops;

void mipv6_protocol_init();
void mipv6_proto_mn_init();
void mipv6_proto_cn_init();

void mipv6_clear_binding_cache();

void mipv6_init_binding_context(mipv6_binding_context_t *,
				mblty_network_address_t *hoa,
				struct in6_addr *destination);
void mipv6_remove_binding_context(mipv6_binding_context_t *);

const char *mipv6_error_description(mipv6_binding_context_t *);
const char *mipv6_ack_status_name(int status);

void mipv6_update_binding(mipv6_binding_context_t *, mblty_address_t *);
void mipv6_clear_binding(mipv6_binding_context_t *);
void mipv6_reset_binding(mipv6_binding_context_t *);

void mipv6_binding_force_update(mipv6_binding_context_t *);

struct mipv6_bcache_entry *mipv6_create_bcache_entry(mipv6_msgctx_t *);
void mipv6_bcache_remove_entry(mipv6_bcache_entry_t *);
void mipv6_prepare_bcache_entry(mipv6_bcache_entry_t *, struct in6_addr *,
				struct in6_addr *);
void mipv6_bcache_no_longer_pending(mipv6_bcache_entry_t *);
void mipv6_bcache_remove_entry_with_error(mipv6_bcache_entry_t *, int status);

int mipv6_foreach_binding_context(int (*)(mipv6_binding_context_t *, void *),
				  void *);
int mipv6_foreach_bcache_entry(int (*)(mipv6_bcache_entry_t *, void *),
			       void *);

mipv6_binding_context_t *mipv6_get_binding_context(struct in6_addr *hoa,
						   struct in6_addr *remo);
mipv6_bcache_entry_t *mipv6_bcache_get_entry(struct in6_addr *hoa,
					     struct in6_addr *local);

void mipv6_build_homepfx_anycast(struct in6_addr *, struct in6_prefix *);

int mipv6_validate_message(mipv6_msgctx_t *, size_t hdrlen);

/* message building and sending */
int mipv6_sendmsg(mipv6_mh_bld_ctx_t *, struct in6_addr *src,
		  struct in6_addr *dst, struct in6_addr *indsrc,
		  struct in6_addr *inddst);
void mipv6_build_header(struct ip6_mh *, size_t size, int type);
struct ip6_mh_opt *mipv6_first_opt(void *, size_t);
struct ip6_mh_opt *mipv6_next_opt(struct ip6_mh_opt *, size_t *length);

struct mipv6_mh_bld_ctx {
	union {
		void *raw;
		struct ip6_mh *mh;
	} h;

	uint8_t *mobopt;
	size_t length;
};

void *mipv6_mh_start(mipv6_mh_bld_ctx_t *, size_t mh_len);
uint8_t *mipv6_mh_pad(mipv6_mh_bld_ctx_t *, int x, int y);
void *mipv6_mh_add_opt(mipv6_mh_bld_ctx_t *, int x, int y, int type, size_t);

void mipv6_proto_register_handler(int type, void (*)(mipv6_msgctx_t *), int);
void mipv6_proto_register_prob_handler(int, void (*)(mipv6_msgctx_t *), int);

#endif /* _MIPV6_PRIV_PROTOCOL_H_ */
