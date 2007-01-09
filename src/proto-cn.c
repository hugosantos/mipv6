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

#include <mblty/icmpv6.h>
#include <mblty/router.h>
#include <mblty/base-support.h>
#include <mblty/sock-support.h>

#include <mipv6/os.h>
#include <mipv6/mipv6.h>
#include <mipv6/protocol.h>
#include <mipv6/proto-sec.h>

static LIST_DEF(binding_cache);

static inline struct in6_addr *
bce_coa(struct mipv6_bcache_entry *bce)
{
	if (bce->flags & MIPV6_BCE_VALID)
		return &bce->active_coa;
	return NULL;
}

static int
generic_send_bu_ack(mipv6_responder_auth_data_t *auth, struct in6_addr *from,
		    struct in6_addr *hoa, struct in6_addr *acfrom,
		    struct in6_addr *coa, int status, int lifetime, int seq)
{
	char buf1[INET6_ADDRSTRLEN], buf2[INET6_ADDRSTRLEN];
	struct ip6_mh_binding_ack *bu_ack;
	struct mipv6_mh_bld_ctx msgctx;

	debug_log(2, "Sending Binding Ack to %s from %s with status %s.\n",
		  format_addr(buf1, hoa), format_addr(buf2, from),
		  mipv6_ack_status_name(status));

	bu_ack = mipv6_mh_start(&msgctx, sizeof(struct ip6_mh_binding_ack));

	bu_ack->ip6mhba_status = status;
	bu_ack->ip6mhba_flags = 0;
	bu_ack->ip6mhba_seqno = htons(seq);
	bu_ack->ip6mhba_lifetime = htons(lifetime);

	if (auth)
		auth->ops->auth_bu_ack(auth, &msgctx, hoa, coa, from);
	else
		mipv6_mh_pad(&msgctx, 8, 0);

	debug_assert((msgctx.length % 8) == 0,
		     "Binding Ack was not properly aligned.");

	mipv6_build_header(msgctx.h.mh, msgctx.length, IP6_MH_TYPE_BACK);

	return mipv6_sendmsg(&msgctx, from, hoa, acfrom, coa);
}

static void
mipv6_bc_entry_send_bu_ack(mipv6_bcache_entry_t *entry, int status)
{
	mipv6_responder_auth_data_t *auth = entry->pending_auth;
	int lifetime = MIPV6_BU_LIFETIME(entry->lifetime);
	struct in6_addr *lcoa = NULL;

	if (entry->reverse && entry->reverse->coa)
		lcoa = &entry->reverse->coa->address;

	generic_send_bu_ack(auth, &entry->local, &entry->hoa, lcoa,
			    &entry->coa, status, lifetime, entry->sequence);

	if (entry->pending_auth) {
		entry->pending_auth->ops->release(entry->pending_auth);
		entry->pending_auth = NULL;
	}
}

void
mipv6_bcache_remove_entry_with_error(mipv6_bcache_entry_t *entry, int status)
{
	mipv6_bc_entry_send_bu_ack(entry, status);
	mipv6_bcache_remove_entry(entry);
}

static void
bcache_bcache_update(struct mipv6_bcache_entry *entry)
{
	kern_bcache_update(&entry->local, &entry->hoa, OS_BCE_DIR_REMOTE,
			   bce_coa(entry), NULL, NULL);
}

static void
bcentry_update_registration(struct mipv6_bcache_entry *entry)
{
	uint32_t value = entry->lifetime * 1000;

	if (entry->flags & MIPV6_BCE_VALID)
		timer_update(&entry->lifetime_timer, value);
	else
		timer_add(&entry->lifetime_timer, value);

	entry->flags |= MIPV6_BCE_VALID;
}

static void
bcentry_update(struct mipv6_bcache_entry *entry)
{
	char buf1[INET6_ADDRSTRLEN], buf2[INET6_ADDRSTRLEN];
	int wasvalid = (entry->flags & MIPV6_BCE_VALID);

	bcentry_update_registration(entry);

	if (wasvalid && in6_addr_compare(&entry->coa, &entry->active_coa) == 0)
		return;

	in6_addr_copy(&entry->active_coa, &entry->coa);

	debug_log(1, "MN %s Binding changed to %s\n",
		  format_addr(buf1, &entry->hoa),
		  format_addr(buf2, &entry->coa));

	if (mipv6_proto_ops.binding_changed)
		mipv6_proto_ops.binding_changed(entry, wasvalid);

	bcache_bcache_update(entry);
}

void
mipv6_bcache_no_longer_pending(struct mipv6_bcache_entry *bcentry)
{
	debug_assert(bcentry->flags & MIPV6_BCE_PENDING_UPD,
		     "Internal failure, called no longer pending on"
		     "non-pending bc entry");

	bcentry->flags &= ~MIPV6_BCE_PENDING_UPD;

	bcentry_update(bcentry);

	if (bcentry->flags & MIPV6_BCE_WANTS_ACK) {
		bcentry->flags &= ~MIPV6_BCE_WANTS_ACK;
		mipv6_bc_entry_send_bu_ack(bcentry, IP6_MH_BAS_ACCEPTED);
	}
}

struct mipv6_bcache_entry *
mipv6_bcache_get_entry(struct in6_addr *hoa, struct in6_addr *local)
{
	struct mipv6_bcache_entry *entry;

	list_for_each_entry (entry, &binding_cache, entry) {
		if (hoa && in6_addr_compare(hoa, &entry->hoa) != 0)
			continue;
		if (local && in6_addr_compare(local, &entry->local) != 0)
			continue;
		return entry;
	}

	return NULL;
}


static void
gen_reply_with_bu_back(mipv6_responder_auth_data_t *auth, mipv6_msgctx_t *msg,
		       mipv6_binding_context_t *rev, int status, uint16_t seq)
{
	struct ip6_mh_binding_update *bu = msg->u.raw;
	struct in6_addr *hoa, *coa, *lcoa = NULL;

	if (msg->hoa == NULL) {
		hoa = msg->from;
		coa = NULL;
	} else {
		hoa = msg->hoa;
		coa = msg->from;
	}

	if (rev && rev->coa)
		lcoa = &rev->coa->address;

	generic_send_bu_ack(auth, msg->to, hoa, lcoa, coa, status,
			    ntohs(bu->ip6mhbu_lifetime), seq);

	if (auth)
		auth->ops->release(auth);
}

static void
reply_with_bu_back(mipv6_responder_auth_data_t *auth, mipv6_msgctx_t *msg,
		   mipv6_binding_context_t *reverse, int status)
{
	struct ip6_mh_binding_update *bu = msg->u.raw;

	gen_reply_with_bu_back(auth, msg, reverse, status,
			       ntohs(bu->ip6mhbu_seqno));
}

static void
reply_bu_back_accepted(mipv6_responder_auth_data_t *auth, mipv6_msgctx_t *msg,
		       mipv6_binding_context_t *rev)
{
	struct ip6_mh_binding_update *bu = msg->u.raw;

	if (ntohs(bu->ip6mhbu_flags) & IP6_MH_BU_ACK)
		reply_with_bu_back(auth, msg, rev, IP6_MH_BAS_ACCEPTED);
}

static struct in6_addr *
bu_contained_coa(struct ip6_mh_binding_update *msg, size_t length,
		 struct in6_addr *from)
{
	size_t optlen = length - sizeof(struct ip6_mh_binding_update);
	struct in6_addr *coa = from;
	struct ip6_mh_opt *mopt;

	for (mopt = mipv6_first_opt(msg + 1, optlen); mopt != NULL;
			mopt = mipv6_next_opt(mopt, &optlen)) {
		if (mopt->ip6mhopt_type == IP6_MHOPT_ALTCOA)
			coa = &((struct ip6_mh_opt_altcoa *)mopt)->ip6moa_addr;
	}

	return coa;
}

static void
mipv6_handle_expired_bcache_entry(suptimer_t *timer, void *arg)
{
	struct mipv6_bcache_entry *entry = arg;

	entry->flags &= ~MIPV6_BCE_VALID;

	if (entry->cb_entry_expired)
		entry->cb_entry_expired(entry);
	mipv6_bcache_remove_entry(entry);
}

void
mipv6_prepare_bcache_entry(struct mipv6_bcache_entry *entry,
			   struct in6_addr *hoa, struct in6_addr *local)
{
	char buf1[INET6_ADDRSTRLEN], buf2[INET6_ADDRSTRLEN];

	in6_addr_copy(&entry->local, local);
	in6_addr_copy(&entry->hoa, hoa);
	in6_addr_copy(&entry->coa, &in6addr_any);
	entry->lifetime = 0;
	entry->flags = 0;
	timer_init_with(&entry->lifetime_timer, "binding cache entry",
			mipv6_handle_expired_bcache_entry, entry);

	entry->cb_destructor = NULL;
	entry->cb_entry_expired = NULL;

	list_add_tail(&entry->entry, &binding_cache);

	debug_log(1, "New binding cache entry (%s, %s)\n",
		  format_addr(buf1, hoa), format_addr(buf2, local));

	entry->pending_auth = NULL;

	entry->reverse = mipv6_get_binding_context(local, hoa);
	if (entry->reverse)
		entry->reverse->reverse = entry;
}

struct mipv6_bcache_entry *
mipv6_create_bcache_entry(struct mipv6_msgctx *msg)
{
	struct mipv6_bcache_entry *entry;

	entry = allocate_object(struct mipv6_bcache_entry);
	if (entry == NULL)
		return NULL;

	mipv6_prepare_bcache_entry(entry, msg->hoa, msg->to);

	return entry;
}

void
mipv6_bcache_remove_entry(struct mipv6_bcache_entry *entry)
{
	if (entry->reverse)
		entry->reverse->reverse = NULL;

	list_del(&entry->entry);

	if (entry->flags & MIPV6_BCE_VALID) {
		timer_remove(&entry->lifetime_timer);
		entry->flags &= ~MIPV6_BCE_VALID;
	}

	bcache_bcache_update(entry);

	if (entry->pending_auth) {
		entry->pending_auth->ops->release(entry->pending_auth);
		entry->pending_auth = NULL;
	}

	if (entry->cb_destructor)
		entry->cb_destructor(entry);
	else
		free_object(entry);
}

static inline int
seq_last_or_equal(int seqtest, int seqbase)
{
	if (seqbase > 32768)
		return seqtest <= seqbase && seqtest >= (seqbase - 32768);
	else
		return seqtest <= seqbase || seqtest >= (seqbase + seqtest);
}

static void
mipv6_handle_bu2(mipv6_msgctx_t *msg, mipv6_bcache_entry_t *bcentry,
		 mipv6_responder_auth_data_t *auth,
		 mipv6_binding_context_t *rev, struct in6_addr *coa)
{
	struct ip6_mh_binding_update *bu = msg->u.raw;
	uint16_t seqno, lifetime;
	int created = 0;

	seqno = ntohs(bu->ip6mhbu_seqno);
	lifetime = ntohs(bu->ip6mhbu_lifetime);

	if (bcentry == NULL) {
		if (bu->ip6mhbu_lifetime == 0) {
			/* user wants to timeout the state, but there is
			 * no state. we reply immediatly. */
			reply_bu_back_accepted(auth, msg, rev);
			return;
		}

		if (mipv6_proto_ops.create_bcache_entry)
			bcentry = mipv6_proto_ops.create_bcache_entry(msg);
		else
			bcentry = mipv6_create_bcache_entry(msg);

		if (bcentry == NULL) {
			reply_with_bu_back(auth, msg, rev,
					   IP6_MH_BAS_INSUFFICIENT);
			return;
		}

		rev = bcentry->reverse;
		created = 1;
	} else {
		/* if already exists a binding cache entry
		 * check if sequence number is acceptable */
		if (seq_last_or_equal(seqno, bcentry->sequence)) {
			gen_reply_with_bu_back(auth, msg, rev,
					       IP6_MH_BAS_SEQNO_BAD,
					       bcentry->sequence);
			return;
		}

		/* if it is acceptable, check if this is a de-registration. */
		if (bu->ip6mhbu_lifetime == 0) {
			reply_bu_back_accepted(auth, msg, rev);
			mipv6_bcache_remove_entry(bcentry);
			return;
		}
	}

	bcentry->sequence = seqno;
	bcentry->lifetime = MIPV6_GET_BU_LIFETIME(lifetime);
	in6_addr_copy(&bcentry->coa, coa);
	bcentry->flags &= ~MIPV6_BCE_WANTS_ACK;

	if (created && mipv6_proto_ops.post_create_bcache_entry)
		mipv6_proto_ops.post_create_bcache_entry(bcentry);

	if (bcentry->pending_auth) {
		bcentry->pending_auth->ops->release(bcentry->pending_auth);
		bcentry->pending_auth = NULL;
	}

	if (bcentry->flags & MIPV6_BCE_PENDING_UPD) {
		/* if the state is pending, we leave the update for later */
		if (ntohs(bu->ip6mhbu_flags) & IP6_MH_BU_ACK) {
			bcentry->flags |= MIPV6_BCE_WANTS_ACK;
			if (auth)
				bcentry->pending_auth = auth->ops->clone(auth);
		}
	} else {
		bcentry_update(bcentry);
		reply_bu_back_accepted(auth, msg, rev);
	}
}

static void
mipv6_handle_binding_update(struct mipv6_msgctx *msg)
{
	int expected = sizeof(struct ip6_mh_binding_update);
	struct ip6_mh_binding_update *bu = msg->u.raw;
	mipv6_responder_auth_data_t *auth = NULL;
	struct in6_addr *hoa = msg->hoa, *coa;
	mipv6_bcache_entry_t *bcentry;
	mipv6_binding_context_t *rev;
	int res;

	if (mipv6_validate_message(msg, expected) < 0)
		return;

	coa = bu_contained_coa(bu, msg->msglen, msg->from);

	if (hoa == NULL) {
		if (bu->ip6mhbu_lifetime == 0) {
			coa = hoa = msg->from;
		} else {
			debug_log(2, "Binding update without HoA option?\n");
			return;
		}
	}

	bcentry = mipv6_bcache_get_entry(hoa, msg->to);
	if (bcentry)
		rev = bcentry->reverse;
	else
		rev = mipv6_get_binding_context(msg->to, hoa);

	res = mipv6_proto_ops.authorize_binding(&auth, bcentry, hoa, coa, msg);
	if (res != IP6_MH_BAS_ACCEPTED) {
		/* Binding not authorized, negative value = silent drop */
		if (res > 0)
			reply_with_bu_back(auth, msg, rev, res);
		return;
	}

	mipv6_handle_bu2(msg, bcentry, auth, rev, coa);

	if (auth)
		auth->ops->release(auth);
}

int
mipv6_foreach_bcache_entry(int (*cb)(struct mipv6_bcache_entry *, void *),
			   void *cb_arg)
{
	struct mipv6_bcache_entry *bcentry, *tmp;
	int res;

	list_for_each_entry_safe (bcentry, tmp, &binding_cache, entry) {
		if ((res = cb(bcentry, cb_arg)) != 0)
			break;
	}

	return res;
}

void
mipv6_clear_binding_cache()
{
	struct mipv6_bcache_entry *bcentry;

	while (list_get_head(bcentry, &binding_cache, entry)) {
		mipv6_bcache_remove_entry(bcentry);
	}
}

void
mipv6_build_homepfx_anycast(struct in6_addr *addr, struct in6_prefix *pfx)
{
	in6_addr_copy(addr, &pfx->address);
	addr->s6_addr[ 8] = 0xfe;
	addr->s6_addr[ 9] = 0xff;
	addr->s6_addr[10] = 0xff;
	addr->s6_addr[11] = 0xff;
	addr->s6_addr[12] = 0xff;
	addr->s6_addr[13] = 0xff;
	addr->s6_addr[14] = 0xff;
	addr->s6_addr[15] = 0xfe;
}

static void
proto_cn_register_handlers(int on)
{
	mipv6_proto_register_handler(IP6_MH_TYPE_BU,
				     mipv6_handle_binding_update, on);
}

static void
mipv6_proto_cn_shutdown()
{
	mipv6_clear_binding_cache();
	proto_cn_register_handlers(0);
}

static struct mblty_shutdown_entry proto_cn_shutdown = {
	.handler = mipv6_proto_cn_shutdown,
};

void
mipv6_proto_cn_init()
{
	proto_cn_register_handlers(1);
	mblty_register_shutdown(&proto_cn_shutdown);
}

