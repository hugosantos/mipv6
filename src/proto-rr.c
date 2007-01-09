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

#include <mblty/ipsec.h>
#include <mblty/router.h>
#include <mblty/interface.h>
#include <mblty/base-support.h>

#include <mipv6/mipv6.h>
#include <mipv6/protocol.h>
#include <mipv6/proto-sec.h>

#include "sec-openssl.h"

#define RR_NONCE_SIZE		8
#define RR_COOKIE_SIZE		8
#define RR_KGT_SIZE		8
#define RR_KBM_SIZE		20
#define RR_KCN_SIZE		20

#define MAX_NONCE_LIFETIME	240
#define MAX_TOKEN_LIFETIME	210

#define RR_NUM_NONCES		8
#define RR_NONCE_REGEN_RATE	(MAX_NONCE_LIFETIME - MAX_TOKEN_LIFETIME)

#define RR_RTX_COUNT		3
#define RR_RTX_TIMEOUT		2000 /* 2 secs RTT */

#define RR_AUTH_DATA_LEN	(96 / 8)

enum {
	RR_AUTHERR_NOSUPP		= 1,
	RR_AUTHERR_TIMEOUT,
};

enum {
	RR_KGT_HOME,
	RR_KGT_CAREOF
};

struct rr_nonce {
	uint8_t data[RR_NONCE_SIZE];
	uint16_t index;
};

struct rr_cookie {
	uint8_t data[RR_COOKIE_SIZE];
};

struct rr_keygen_token {
	uint8_t data[RR_KGT_SIZE];
};

struct rr_kbm {
	uint8_t data[RR_KBM_SIZE];
};

struct rr_single_auth_data {
	struct rr_cookie cookie;
	struct rr_keygen_token token;
	uint16_t nonce_index;

#define RR_SAD_VALID		0x0001
#define RR_SAD_WAITING_REPLY	0x0002
	uint16_t flags;

	suptimer_t token_timer;
	int rtx_count, rtx_timeout;
};

struct rr_auth_data {
	struct mipv6_auth_data base;

#define RR_AUTH_HAS_KBM		0x0001
#define RR_AUTH_FAILED		0x0002
	uint32_t flags;

	/* this pointer is valid during the update */
	mblty_address_t *pending_coa;

	struct rr_kbm kbm;
	struct rr_single_auth_data home, careof;
};

struct rr_resp_auth_data {
	mipv6_responder_auth_data_t base;
	struct rr_kbm kbm;
#define RR_RESP_AD_ALLOCED	0x0001
	uint32_t flags;
};

struct rr_resp_auth {
	mipv6_responder_auth_t base;
	struct rr_resp_auth_data strad;
};

static struct rr_nonce nonces[RR_NUM_NONCES];
static int nonces_first;
static uint16_t nonces_offset;
static suptimer_t nonce_timer;

static uint8_t Kcn[RR_KCN_SIZE];

static void rr_resp_auth_data_setup_ops(struct rr_resp_auth_data *);

static void
rr_generate_token(uint8_t *kgtbuf, struct in6_addr *address, int type,
		  struct rr_nonce *nonce)
{
	uint8_t buffer[SHA1_LENGTH];
	struct hmac_sha1_ctx ctx;
	uint8_t byte;

	byte = (type == RR_KGT_HOME) ? 0 : 1;

	hmac_sha1_init_with_key(&ctx, Kcn, sizeof(Kcn));

	hmac_sha1_add_data(&ctx, address->s6_addr, sizeof(struct in6_addr));
	hmac_sha1_add_data(&ctx, nonce->data, RR_NONCE_SIZE);
	hmac_sha1_add_data(&ctx, &byte, 1);

	hmac_sha1_obtain(&ctx, buffer);

	memcpy(kgtbuf, buffer, RR_KGT_SIZE);
}

static void
rr_generate_kbm(struct rr_kbm *kbm, struct rr_keygen_token *home,
		struct rr_keygen_token *careof)
{
	struct sha1_ctx ctx;

	sha1_init(&ctx);

	sha1_add_data(&ctx, home->data, RR_KGT_SIZE);

	if (careof)
		sha1_add_data(&ctx, careof->data, RR_KGT_SIZE);

	sha1_obtain(&ctx, kbm->data);
}

static void
rr_generate_auth_data(uint8_t *t, struct rr_kbm *kbm, struct in6_addr *coa,
		      struct in6_addr *cn, struct ip6_mh *mh, int mh_len)
{
	uint8_t buffer[SHA1_LENGTH];
	struct hmac_sha1_ctx ctx;

	hmac_sha1_init_with_key(&ctx, kbm->data, RR_KBM_SIZE);

	hmac_sha1_add_data(&ctx, coa->s6_addr, sizeof(struct in6_addr));
	hmac_sha1_add_data(&ctx, cn->s6_addr, sizeof(struct in6_addr));
	hmac_sha1_add_data(&ctx, (uint8_t *)mh, mh_len);

	hmac_sha1_obtain(&ctx, buffer);

	memcpy(t, buffer, RR_AUTH_DATA_LEN);
}

static struct rr_nonce *
rr_get_younger_nonce()
{
	return &nonces[nonces_first];
}

static struct rr_nonce *
rr_get_nonce(uint16_t nonce_index)
{
	int real_index;

	if ((nonce_index < nonces_offset) ||
	    (nonce_index >= (nonces_offset + RR_NUM_NONCES)))
		return NULL;

	/* nonces_offset => index of the oldest nonce
	 * A = nonces_first + 1 => position of the oldest nonce
	 * B = index - nonces_offset => this index's distance to oldest nonce
	 * A+B = position of this index */

	/* get oldest nonce position */
	real_index  = nonces_first + 1;
	/* add the distance to the oldest nonce */
	real_index += nonce_index - nonces_offset;
	/* this is a circular list */
	real_index %= RR_NUM_NONCES;

	debug_assert(nonces[real_index].index == nonce_index,
		     "Nonce logic failed badly.");

	return &nonces[real_index];
}

static inline int
rr_auth_mh_data_len(struct ip6_mh *mh, struct ip6_mh_opt_auth_data *data)
{
	/* RFC 3775, Section 6.2.7:
	 *   "MH Data" is the content of the Mobility Header, excluding
	 *   the Authenticator field itself. */

	return ((uint8_t *)&data->ip6moad_data[0]) - (uint8_t *)mh;
}

static inline struct rr_auth_data *
rr_auth_data(mipv6_binding_context_t *ctx)
{
	return container_of(ctx->auth, struct rr_auth_data, base);
}

/* checks if authentication should be used for the binding update and
 * if so adds an auth data mobility option to the end of the message
 * and calculates the authenticator */
static void
rr_auth_bu(mipv6_binding_context_t *ctx, mipv6_mh_bld_ctx_t *bld)
{
	struct rr_auth_data *auth_data = rr_auth_data(ctx);
	struct ip6_mh_binding_update *bu = bld->h.raw;
	struct ip6_mh_opt_auth_data *auth_data_opt;
	struct ip6_mh_opt_nonce_index *nindex;
	uint8_t *authenticator;
	int length;

	if (!(auth_data->flags & RR_AUTH_HAS_KBM))
		return;

	/* adds the return routability required mobility options
	 * (nonce indexes) to the specified message */
	nindex = mipv6_mh_add_opt(bld, 2, 0, IP6_MHOPT_NONCEID,
				  sizeof(struct ip6_mh_opt_nonce_index));

	nindex->ip6moni_home_nonce = htons(auth_data->home.nonce_index);
	nindex->ip6moni_coa_nonce = htons(auth_data->careof.nonce_index);
	if (bu->ip6mhbu_lifetime == 0)
		nindex->ip6moni_coa_nonce = 0;

	/* start authentication data mobility option */
	auth_data_opt = mipv6_mh_add_opt(bld, 8, 2, IP6_MHOPT_BAUTH,
					 sizeof(struct ip6_mh_opt_auth_data));

	/* set proper values in the mobility header */
	mipv6_build_header(bld->h.mh, bld->length, IP6_MH_TYPE_BU);

	length = rr_auth_mh_data_len(bld->h.mh, auth_data_opt);
	authenticator = auth_data_opt->ip6moad_data;

	if (bu->ip6mhbu_lifetime == 0) {
		/* this is a de-registration, we'll use a Kbm
		 * generated only with the HoA */
		struct in6_addr *hoa = mblty_get_addr(ctx->hoa);
		struct rr_kbm kbm_stor;

		rr_generate_kbm(&kbm_stor, &auth_data->home.token, NULL);

		rr_generate_auth_data(authenticator, &kbm_stor, hoa,
				      ctx->destination, bld->h.mh, length);
		return;
	}

	rr_generate_auth_data(authenticator, &auth_data->kbm,
			      &ctx->coa->address, ctx->destination,
			      bld->h.mh, length);
}

static int
rr_auth_bu_ack(mipv6_binding_context_t *ctx, struct in6_addr *coa,
	       struct ip6_mh_binding_ack *back, size_t length)
{
	size_t optlen = length - sizeof(struct ip6_mh_binding_update);
	struct rr_auth_data *auth_data = rr_auth_data(ctx);
	struct ip6_mh_opt_auth_data *auth_data_opt = NULL;
	struct ip6_mh_opt *mobopt = NULL, *lastopt = NULL;
	struct rr_kbm kbm_stor, *kbm = &auth_data->kbm;
	struct in6_addr *hoa = mblty_get_addr(ctx->hoa);
	uint8_t authenticator[RR_AUTH_DATA_LEN];

	for (mobopt = mipv6_first_opt(back + 1, optlen); mobopt;
			mobopt = mipv6_next_opt(mobopt, &optlen)) {
		if (mobopt->ip6mhopt_type == IP6_MHOPT_BAUTH)
			auth_data_opt = (struct ip6_mh_opt_auth_data *)mobopt;

		lastopt = mobopt;
	}

	if (auth_data_opt == NULL)
		return 0;

	/* Was the Authentication data opt the last one? */
	if (lastopt != (struct ip6_mh_opt *)auth_data_opt)
		return -1;

	if (coa == NULL) {
		rr_generate_kbm(&kbm_stor, &auth_data->home.token, NULL);
		kbm = &kbm_stor;
	}

	rr_generate_auth_data(authenticator, kbm, coa ? coa : hoa,
			      ctx->destination, &back->ip6mhba_mh,
			      rr_auth_mh_data_len(&back->ip6mhba_mh,
						  auth_data_opt));

	/* does the authentication data match */
	if (memcmp(auth_data_opt->ip6moad_data, authenticator,
		   sizeof(authenticator))) {
		debug_log(5, "BU-Ack Authentication data doesn't match\n");
		return -1;
	}

	return 0;
}

static int
rr_is_valid(mipv6_binding_context_t *ctx)
{
	return rr_auth_data(ctx)->flags & RR_AUTH_HAS_KBM;
}

static void
rr_sad_cancel_update(mipv6_binding_context_t *ctx,
		     struct rr_single_auth_data *data)
{
	if (data->flags & RR_SAD_WAITING_REPLY) {
		data->flags &= ~RR_SAD_WAITING_REPLY;
		timer_remove(&data->token_timer);
	}
}

static void
rr_cancel_update(mipv6_binding_context_t *ctx, mblty_address_t *coa)
{
	struct rr_auth_data *auth_data = rr_auth_data(ctx);

	if (coa && coa != auth_data->pending_coa)
		return;

	rr_sad_cancel_update(ctx, &auth_data->home);
	rr_sad_cancel_update(ctx, &auth_data->careof);

	mblty_put_address(auth_data->pending_coa);
	auth_data->pending_coa = NULL;
}

static void
rr_failed(mipv6_binding_context_t *ctx, int why)
{
	struct rr_auth_data *auth_data = rr_auth_data(ctx);

	auth_data->flags |= RR_AUTH_FAILED;

	debug_log(4, "RR failed: %i\n", why);

	rr_cancel_update(ctx, NULL);

	if (ctx->auth->failed)
		ctx->auth->failed(ctx->auth);
}

static uint8_t *
rr_generate_cookie(struct rr_cookie *cookie)
{
	return random_pseudo_bytes(cookie->data, RR_COOKIE_SIZE);
}

/* generates and sends a HOTI or COTI message */
static void
rr_send_xoti(mipv6_binding_context_t *ctx, int type,
	     struct rr_single_auth_data *data)
{
	struct rr_auth_data *auth_data = rr_auth_data(ctx);
	mblty_address_t *origin = mblty_addr_parent(ctx->hoa);
	char buf1[INET6_ADDRSTRLEN], buf2[INET6_ADDRSTRLEN];
	struct mipv6_msg_stat_tx *stat = &ctx->stats.hoti;
	int res, mh_type = IP6_MH_TYPE_HOTI;
	/* we use the same structure for both HOTI and COTI, which is OK */
	struct ip6_mh_home_test_init *hoti;
	mipv6_mh_bld_ctx_t msgctx;

	hoti = mipv6_mh_start(&msgctx, sizeof(struct ip6_mh_home_test_init));

	if (type != RR_KGT_HOME) {
		mh_type = IP6_MH_TYPE_COTI;
		origin = auth_data->pending_coa ?
				auth_data->pending_coa : ctx->coa;
	}

	if (data->flags & RR_SAD_WAITING_REPLY) {
		data->rtx_count--;
		data->flags &= ~RR_SAD_WAITING_REPLY;

		if (data->rtx_count == 0) {
			rr_failed(ctx, RR_AUTHERR_TIMEOUT);
			return;
		}

		data->rtx_timeout *= 2;
	} else {
		data->rtx_count = RR_RTX_COUNT;
		data->rtx_timeout = RR_RTX_TIMEOUT;
	}

	data->flags |= RR_SAD_WAITING_REPLY;
	timer_add(&data->token_timer, data->rtx_timeout);

	/* From RFC 3775
	 *   Retransmitted Home Test Init and Care-of Test Init
	 *   messages MUST use new cookie values. */
	memcpy(hoti->ip6mhhti_cookie, rr_generate_cookie(&data->cookie),
	       RR_COOKIE_SIZE);

	mipv6_build_header(msgctx.h.mh, msgctx.length, mh_type);

	debug_log(2, "Sending %cOTI from %s to %s.\n",
		  type == RR_KGT_HOME ? 'H' : 'C',
		  format_addr(buf1, &origin->address),
		  format_addr(buf2, ctx->destination));

	res = mipv6_sendmsg(&msgctx, &origin->address, ctx->destination,
			    NULL, NULL);

	if (type == RR_KGT_CAREOF)
		stat = &ctx->stats.coti;

	if (res < 0)
		stat->failed++;
	else
		stat->tx++;
}

static void
rr_update_kgt(mipv6_binding_context_t *ctx, int type)
{
	struct rr_auth_data *auth_data = rr_auth_data(ctx);

	if (type == RR_KGT_HOME)
		rr_send_xoti(ctx, type, &auth_data->home);
	else
		rr_send_xoti(ctx, type, &auth_data->careof);
}

/* retransmit a HOTI or COTI as it may have been lost */
static void
rr_timer_callback(suptimer_t *timer, void *param)
{
	struct mipv6_binding_context *ctx = param;
	struct rr_auth_data *auth_data = rr_auth_data(ctx);
	struct rr_single_auth_data *data;
	int type;

	if (timer == &auth_data->home.token_timer) {
		data = &auth_data->home;
		type = RR_KGT_HOME;
	} else {
		data = &auth_data->careof;
		type = RR_KGT_CAREOF;
	}

	if (data->flags & RR_SAD_WAITING_REPLY)
		rr_send_xoti(ctx, type, data);
	else if (data->flags & RR_SAD_VALID)
		rr_update_kgt(ctx, type);
}

static void
rr_init_single_auth_data(mipv6_binding_context_t *ctx,
			 struct rr_single_auth_data *data)
{
	data->flags = 0;
	memset(&data->cookie, 0, sizeof(struct rr_cookie));
	memset(&data->token, 0, sizeof(struct rr_keygen_token));
	data->nonce_index = 0;
	timer_init_with(&data->token_timer, "single auth data",
			rr_timer_callback, ctx);
	data->rtx_count = 0;
	data->rtx_timeout = 0;
}

static void
rr_invalidate_sad(struct rr_single_auth_data *data)
{
	if (data->flags & RR_SAD_VALID)
		data->flags &= ~RR_SAD_VALID;
	else if (data->flags & RR_SAD_WAITING_REPLY)
		data->flags &= ~RR_SAD_WAITING_REPLY;
	else
		return;

	timer_remove(&data->token_timer);
}

static void
rr_invalidate_auth_data(struct rr_auth_data *data)
{
	rr_invalidate_sad(&data->home);
	rr_invalidate_sad(&data->careof);

	data->flags &= ~RR_AUTH_HAS_KBM;
}

static void
rr_release_auth_data(mipv6_auth_data_t *auth_data)
{
	struct rr_auth_data *rrad =
		container_of(auth_data, struct rr_auth_data, base);

	rr_invalidate_auth_data(rrad);
	free_object(rrad);
}

static void
rr_clear_data(mipv6_binding_context_t *ctx)
{
	struct rr_auth_data *auth_data = rr_auth_data(ctx);

	rr_cancel_update(ctx, NULL);
	rr_invalidate_auth_data(auth_data);

	/* Clear failure status (if set) as well */
	auth_data->flags = 0;
}

/* if Home or Careof- data is not valid, trigger HOTI/COTI */
static void
rr_refresh_sad_if_needed(mipv6_binding_context_t *ctx, int type,
			 struct rr_single_auth_data *data)
{
	if (data->flags & RR_SAD_VALID)
		return;

	rr_update_kgt(ctx, type);
}

/* called when an update is requested, for instance when the
 * CoA changes. refreshes the data that needs refreshing */
static void
rr_update(mipv6_binding_context_t *ctx, mblty_address_t *new_coa)
{
	struct rr_auth_data *auth_data = rr_auth_data(ctx);

	if (auth_data->pending_coa == new_coa)
		return;

	mblty_put_address(auth_data->pending_coa);
	auth_data->pending_coa = mblty_get_address(new_coa);

	if (auth_data->flags & RR_AUTH_FAILED) {
		auth_data->flags &= ~RR_AUTH_FAILED;
		rr_invalidate_auth_data(auth_data);
	}

	rr_refresh_sad_if_needed(ctx, RR_KGT_HOME,
				 &auth_data->home);

	/* is CoA changing? */
	if (ctx->coa != new_coa)
		rr_invalidate_sad(&auth_data->careof);

	rr_refresh_sad_if_needed(ctx, RR_KGT_CAREOF,
				 &auth_data->careof);
}

/* called when both keygen tokens are available and are valid
 * to generate the Kbm */
static void
rr_update_kbm(mipv6_binding_context_t *ctx)
{
	struct rr_auth_data *auth_data = rr_auth_data(ctx);
	/* int had = (auth_data->flags & RR_AUTH_HAS_KBM); */

	rr_generate_kbm(&auth_data->kbm, &auth_data->home.token,
			&auth_data->careof.token);

	auth_data->flags |= RR_AUTH_HAS_KBM;

	if (ctx->auth->updated)
		ctx->auth->updated(ctx->auth);
}

static void
rr_updated_token(mipv6_binding_context_t *ctx, int type)
{
	struct rr_auth_data *auth_data = rr_auth_data(ctx);
	struct rr_single_auth_data *data;

	if (type == RR_KGT_HOME) {
		data = &auth_data->home;
	} else {
		data = &auth_data->careof;
		mblty_put_address(auth_data->pending_coa);
		auth_data->pending_coa = NULL;
	}

	data->flags |= RR_SAD_VALID;
	timer_add(&data->token_timer, 180000);

	if ((auth_data->home.flags & RR_SAD_VALID) &&
	    (auth_data->careof.flags & RR_SAD_VALID))
		rr_update_kbm(ctx);
}

/* called to handle HOT or COT */
static int
rr_handle_xot(mipv6_binding_context_t *ctx, int type,
	      struct rr_single_auth_data *data,
	      struct ip6_mh_home_test *xot)
{
	uint8_t *cookie = data->cookie.data;

	debug_log(4, "rr_handle_xot(%i)\n", type);

	if (!(data->flags & RR_SAD_WAITING_REPLY)) {
		debug_log(5, "Received unwanted %s.\n",
			  type == RR_KGT_HOME ? "HOT" : "COT");
		return -1;
	}

	if (memcmp(cookie, xot->ip6mhht_cookie, RR_COOKIE_SIZE) != 0) {
		debug_log(5, "Bad cookie, not for us.\n");
		return -1;
	}

	data->flags &= ~RR_SAD_WAITING_REPLY;
	timer_remove(&data->token_timer);

	memcpy(data->token.data, xot->ip6mhht_keygen, RR_KGT_SIZE);
	data->nonce_index = ntohs(xot->ip6mhht_nonce_index);

	rr_updated_token(ctx, type);

	return 0;
}

static int
rr_handle_xot0(mipv6_binding_context_t *ctx, int type,
	       struct rr_single_auth_data *rsad, struct ip6_mh_home_test *hot,
	       struct mipv6_msg_stat_rx *stats)
{
	stats->rx++;

	if (rr_handle_xot(ctx, type, rsad, hot) < 0) {
		stats->dscrd++;
		return -1;
	}

	return 0;
}

static int
rr_handle_hot(mipv6_binding_context_t *ctx, struct ip6_mh_home_test *hot)
{
	return rr_handle_xot0(ctx, RR_KGT_HOME, &rr_auth_data(ctx)->home,
			      hot, &ctx->stats.hot);
}

static int
rr_handle_cot(mipv6_binding_context_t *ctx, struct ip6_mh_careof_test *cot)
{
	return rr_handle_xot0(ctx, RR_KGT_CAREOF, &rr_auth_data(ctx)->careof,
			      (struct ip6_mh_home_test *)cot, &ctx->stats.cot);
}

static int
rr_unrecognized_xoti(mipv6_binding_context_t *ctx, int type,
		     struct rr_single_auth_data *data,
		     struct ip6_mh_home_test_init *xoti)
{
	uint8_t *cookie = data->cookie.data;

	debug_log(3, "RR Unrecognized %cOTI.\n",
		  type == RR_KGT_HOME ? 'H' : 'C');

	if (memcmp(cookie, xoti->ip6mhhti_cookie, RR_COOKIE_SIZE)) {
		debug_log(3, " Bad Cookie.\n");
		return -1;
	}

	rr_failed(ctx, RR_AUTHERR_NOSUPP);

	return 0;
}

static int
rr_unrecognized_hoti(mipv6_binding_context_t *ctx,
		     struct ip6_mh_home_test_init *hoti)
{
	struct rr_auth_data *auth_data = rr_auth_data(ctx);

	if (auth_data->flags & RR_AUTH_FAILED)
		return -1;

	return rr_unrecognized_xoti(ctx, RR_KGT_HOME, &auth_data->home, hoti);
}

static int
rr_unrecognized_coti(mipv6_binding_context_t *ctx, struct in6_addr *coa,
		     struct ip6_mh_careof_test_init *coti)
{
	struct rr_auth_data *auth_data = rr_auth_data(ctx);

	if (auth_data->flags & RR_AUTH_FAILED)
		return -1;

	if (auth_data->pending_coa) {
		if (in6_addr_compare(&auth_data->pending_coa->address, coa))
			return -1;
	} else {
		return -1;
	}

	return rr_unrecognized_xoti(ctx, RR_KGT_CAREOF, &auth_data->careof,
				    (struct ip6_mh_home_test_init *)coti);
}

static int
rr_generic_send_test_init_reply(mipv6_msgctx_t *msg, struct rr_cookie *c,
				int mh_type, int type)
{
	struct rr_nonce *nonce = rr_get_younger_nonce();
	struct ip6_mh_home_test *hot;
	char buf1[INET6_ADDRSTRLEN];
	mipv6_mh_bld_ctx_t ctx;

	hot = mipv6_mh_start(&ctx, sizeof(struct ip6_mh_home_test));

	hot->ip6mhht_nonce_index = htons(nonce->index);
	memcpy(hot->ip6mhht_cookie, c->data, RR_COOKIE_SIZE);
	rr_generate_token((uint8_t *)hot->ip6mhht_keygen, msg->from,
			  type, nonce);

	/* align header to 8n */
	mipv6_mh_pad(&ctx, 8, 0);

	mipv6_build_header(ctx.h.mh, ctx.length, mh_type);

	debug_log(3, "sending %cOT to %s\n", type == RR_KGT_HOME ?
		  'H' : 'C', format_addr(buf1, msg->from));

	return mipv6_sendmsg(&ctx, msg->to, msg->from, NULL, NULL);
}

static void
rr_handle_hoti(struct mipv6_msgctx *msg)
{
	struct ip6_mh_home_test_init *hoti = msg->u.raw;
	int len = sizeof(struct ip6_mh_home_test_init);
	struct rr_cookie cookie;

	if (mipv6_validate_message(msg, len) < 0)
		return;

	/* did the message contain a Home Address DST Opt? */
	if (msg->hoa != NULL)
		return;

	memcpy(cookie.data, hoti->ip6mhhti_cookie, RR_COOKIE_SIZE);

	rr_generic_send_test_init_reply(msg, &cookie, IP6_MH_TYPE_HOT,
					RR_KGT_HOME);
}

static void
rr_handle_coti(struct mipv6_msgctx *msg)
{
	struct ip6_mh_careof_test_init *coti = msg->u.raw;
	int len = sizeof(struct ip6_mh_home_test_init);
	struct rr_cookie cookie;

	if (mipv6_validate_message(msg, len) < 0)
		return;

	/* did the message contain a Home Address DST Opt? */
	if (msg->hoa != NULL)
		return;

	memcpy(cookie.data, coti->ip6mhcti_cookie, RR_COOKIE_SIZE);

	rr_generic_send_test_init_reply(msg, &cookie, IP6_MH_TYPE_COT,
					RR_KGT_CAREOF);
}

static void
rr_handle_hoa_test(struct mipv6_msgctx *msg)
{
	struct ip6_mh_home_test *hot = msg->u.raw;
	struct mipv6_binding_context *ctx;

	if (mipv6_validate_message(msg, sizeof(struct ip6_mh_home_test)) < 0)
		return;

	ctx = mipv6_get_binding_context(msg->to, msg->from);
	if (ctx == NULL) {
		char buf1[INET6_ADDRSTRLEN], buf2[INET6_ADDRSTRLEN];

		debug_log(4, "No context for HOT to %s from %s.\n",
			  format_addr(buf1, msg->to),
			  format_addr(buf2, msg->from));
		return;
	}

	rr_handle_hot(ctx, hot);
}

static int
rr_check_handle_coa_test(mipv6_binding_context_t *ctx, void *param)
{
	struct mipv6_msgctx *msg = param;
	struct ip6_mh_careof_test *cot;

	if (in6_addr_compare(ctx->destination, msg->from) != 0)
		return 0;

	cot = msg->u.raw;

	if (rr_handle_cot(ctx, cot) == 0)
		return 1;

	return 0;
}

static void
rr_handle_coa_test(struct mipv6_msgctx *msg)
{
	char buf1[INET6_ADDRSTRLEN], buf2[INET6_ADDRSTRLEN];

	if (mipv6_validate_message(msg, sizeof(struct ip6_mh_careof_test)) < 0)
		return;

	if (mipv6_foreach_binding_context(rr_check_handle_coa_test, msg) != 0)
		return;

	debug_log(4, "No context for COT to %s from %s.\n",
		  format_addr(buf1, msg->to),
		  format_addr(buf2, msg->from));
}

static void
rr_handle_prob_in_hoti(mipv6_msgctx_t *msgctx)
{
	struct ip6_mh_home_test_init *hoti = msgctx->u.raw;
	mipv6_binding_context_t *ctx;

	if (msgctx->msglen < sizeof(struct ip6_mh_home_test_init))
		return;

	if (msgctx->hoa != NULL)
		return;

	ctx = mipv6_get_binding_context(msgctx->from, msgctx->to);
	if (ctx == NULL)
		return;

	rr_unrecognized_hoti(ctx, hoti);
}

static int
rr_check_handle_prob_in_coti(mipv6_binding_context_t *ctx, void *param)
{
	struct ip6_mh_careof_test_init *coti;
	mipv6_msgctx_t *msgctx = param;

	coti = msgctx->u.raw;

	if (in6_addr_compare(ctx->destination, msgctx->to) != 0)
		return 0;

	if (rr_unrecognized_coti(ctx, msgctx->from, coti) == 0)
		return 1;

	return 0;
}

static void
rr_handle_prob_in_coti(mipv6_msgctx_t *msgctx)
{
	if (msgctx->msglen < sizeof(struct ip6_mh_careof_test_init))
		return;

	if (msgctx->hoa != NULL)
		return;

	mipv6_foreach_binding_context(rr_check_handle_prob_in_coti, msgctx);
}

static void
rr_nonce_generate(struct rr_nonce *nonce, uint16_t nonce_index)
{
	nonce->index = nonce_index;
	random_pseudo_bytes(nonce->data, RR_NONCE_SIZE);
}

static void
rr_nonce_timer_callback(suptimer_t *timer, void *data)
{
	struct rr_nonce *younger;

	nonces_offset++;

	/* advance nonces, we'll update nonces_first + 1,
	 * which was the oldest nonce */
	nonces_first = (nonces_first + 1) % RR_NUM_NONCES;
	younger = rr_get_younger_nonce();
	rr_nonce_generate(younger, younger->index + RR_NUM_NONCES);

	timer_add(&nonce_timer, RR_NONCE_REGEN_RATE * 1000);
}

static inline struct rr_resp_auth_data *
rr_resp_auth_data_from(mipv6_responder_auth_data_t *data)
{
	return container_of(data, struct rr_resp_auth_data, base);
}

static void
rr_resp_auth_bu_ack(mipv6_responder_auth_data_t *data, mipv6_mh_bld_ctx_t *bld,
		    struct in6_addr *hoa, struct in6_addr *coa,
		    struct in6_addr *dest)
{
	struct rr_resp_auth_data *rad = rr_resp_auth_data_from(data);
	struct ip6_mh_opt_auth_data *auth_data_opt;

	/* start authentication data mobility option */
	auth_data_opt = mipv6_mh_add_opt(bld, 8, 2, IP6_MHOPT_BAUTH,
					 sizeof(struct ip6_mh_opt_auth_data));

	/* set proper values in the mobility header */
	mipv6_build_header(bld->h.mh, bld->length, IP6_MH_TYPE_BACK);

	rr_generate_auth_data(auth_data_opt->ip6moad_data, &rad->kbm,
			      coa ? coa : hoa, dest, bld->h.mh,
			      rr_auth_mh_data_len(bld->h.mh, auth_data_opt));
}

static mipv6_responder_auth_data_t *
rr_resp_auth_data_clone(mipv6_responder_auth_data_t *data)
{
	struct rr_resp_auth_data *rad = rr_resp_auth_data_from(data);
	struct rr_resp_auth_data *new;

	new = allocate_object(struct rr_resp_auth_data);
	if (new == NULL)
		return NULL;

	rr_resp_auth_data_setup_ops(new);
	new->flags = rad->flags | RR_RESP_AD_ALLOCED;
	memcpy(&new->kbm, &rad->kbm, sizeof(struct rr_kbm));

	return &new->base;
}

static void
rr_resp_auth_data_release(mipv6_responder_auth_data_t *data)
{
	struct rr_resp_auth_data *rad = rr_resp_auth_data_from(data);

	if (rad->flags & RR_RESP_AD_ALLOCED)
		free_object(rad);
}

static inline struct rr_resp_auth *
rr_resp_auth_from(mipv6_responder_auth_t *data)
{
	return container_of(data, struct rr_resp_auth, base);
}

static int
rr_resp_auth_bu(mipv6_responder_auth_t *resp_auth,
		mipv6_responder_auth_data_t **auth_data,
		struct in6_addr *hoa, struct in6_addr *coa,
		mipv6_msgctx_t *msgctx)
{
	size_t optlen = msgctx->msglen - sizeof(struct ip6_mh_binding_update);
	struct rr_resp_auth *rrra = rr_resp_auth_from(resp_auth);
	struct ip6_mh_opt_auth_data *auth_data_opt = NULL;
	struct ip6_mh_opt *mobopt = NULL, *lastopt = NULL;
	struct ip6_mh_opt_nonce_index *nindex_opt = NULL;
	struct ip6_mh_binding_update *bu = msgctx->u.raw;
	struct rr_resp_auth_data *rad = &rrra->strad;
	struct rr_keygen_token home_kgt, careof_kgt;
	struct rr_nonce *home_nonce, *careof_nonce;
	uint8_t authenticator[RR_AUTH_DATA_LEN];
	struct rr_kbm *kbm = &rad->kbm;

	char buf1[INET6_ADDRSTRLEN], buf2[INET6_ADDRSTRLEN],
	     buf3[INET6_ADDRSTRLEN];

	debug_log(5, "mipv6_rr_authorize_bu(%s, %s, %s, %p, %d)\n",
		  format_addr(buf1, hoa), coa ? format_addr(buf2, coa) : NULL,
		  format_addr(buf3, msgctx->to), bu, msgctx->msglen);

	/* in a de-registering BU, the CoA is not used
	 * for auth. but the HoA instead */
	if (bu->ip6mhbu_lifetime == 0)
		coa = NULL;
	else if (coa == NULL)
		return -1;

	for (mobopt = mipv6_first_opt(bu + 1, optlen); mobopt;
			mobopt = mipv6_next_opt(mobopt, &optlen)) {
		if (mobopt->ip6mhopt_type == IP6_MHOPT_NONCEID) {
			/* duplicate nonce indices? */
			if (nindex_opt)
				return -1;
			nindex_opt = (struct ip6_mh_opt_nonce_index *)mobopt;
		} else if (mobopt->ip6mhopt_type == IP6_MHOPT_BAUTH)
			auth_data_opt = (struct ip6_mh_opt_auth_data *)mobopt;

		lastopt = mobopt;
	}

	if (auth_data_opt) {
		if (nindex_opt == NULL)
			return -1;
	} else
		return IP6_MH_BAS_ACCEPTED;

	/* Was the authentication data opt the last one? */
	if (lastopt != (struct ip6_mh_opt *)auth_data_opt)
		return -1;

	/* get specified nonces */
	home_nonce = rr_get_nonce(ntohs(nindex_opt->ip6moni_home_nonce));
	careof_nonce = rr_get_nonce(ntohs(nindex_opt->ip6moni_coa_nonce));

	if (home_nonce == NULL) {
		if (coa && careof_nonce == NULL)
			return IP6_MH_BAS_NI_EXPIRED;
		return IP6_MH_BAS_HOME_NI_EXPIRED;
	} else if (coa && careof_nonce == NULL)
		return IP6_MH_BAS_COA_NI_EXPIRED;

	rr_resp_auth_data_setup_ops(rad);
	rad->flags = 0;

	/* the checksum was zero when generating */
	bu->ip6mhbu_cksum = 0;

	rr_generate_token(home_kgt.data, hoa, RR_KGT_HOME, home_nonce);
	if (coa) {
		rr_generate_token(careof_kgt.data, coa, RR_KGT_CAREOF,
				  careof_nonce);
	}

	rr_generate_kbm(kbm, &home_kgt, coa ? &careof_kgt : NULL);

	rr_generate_auth_data(authenticator, kbm, coa ? coa : hoa, msgctx->to,
			      &bu->ip6mhbu_mh, rr_auth_mh_data_len(
				      &bu->ip6mhbu_mh, auth_data_opt));

	if (memcmp(auth_data_opt->ip6moad_data, authenticator,
		   sizeof(authenticator))) {
		/* authentication data doesn't match */
		debug_log(5, "Authentication data doesn't match\n");
		return -1;
	}

	(*auth_data) = &rad->base;

	return IP6_MH_BAS_ACCEPTED;
}

static void
rr_resp_auth_release(mipv6_responder_auth_t *resp_auth)
{
	free_object(resp_auth);
}

static void
rr_register_msgs(int on)
{
	mipv6_proto_register_handler(IP6_MH_TYPE_HOTI, rr_handle_hoti, on);
	mipv6_proto_register_handler(IP6_MH_TYPE_COTI, rr_handle_coti, on);
	mipv6_proto_register_handler(IP6_MH_TYPE_HOT, rr_handle_hoa_test, on);
	mipv6_proto_register_handler(IP6_MH_TYPE_COT, rr_handle_coa_test, on);

	mipv6_proto_register_prob_handler(IP6_MH_TYPE_HOTI,
					  rr_handle_prob_in_hoti, on);
	mipv6_proto_register_prob_handler(IP6_MH_TYPE_COTI,
					  rr_handle_prob_in_coti, on);
}

static void
rr_shutdown()
{
	timer_remove(&nonce_timer);
	rr_register_msgs(0);
}

static struct mblty_shutdown_entry proto_sec_shutdown = {
	.handler = rr_shutdown,
};

static mipv6_auth_data_ops_t rr_auth_data_ops = {
	.auth_bu = rr_auth_bu,
	.auth_bu_ack = rr_auth_bu_ack,
	.update = rr_update,
	.cancel = rr_cancel_update,
	.clear = rr_clear_data,
	.is_valid = rr_is_valid,
	.release = rr_release_auth_data,
};

static mipv6_responder_auth_ops_t rr_responder_auth_ops = {
	.auth_bu = rr_resp_auth_bu,
	.release = rr_resp_auth_release,
};

static mipv6_responder_auth_data_ops_t rr_resp_auth_data_ops = {
	.auth_bu_ack = rr_resp_auth_bu_ack,
	.clone = rr_resp_auth_data_clone,
	.release = rr_resp_auth_data_release,
};

static void
rr_resp_auth_data_setup_ops(struct rr_resp_auth_data *data)
{
	data->base.ops = &rr_resp_auth_data_ops;
}

mipv6_auth_data_t *
mipv6_alloc_rr_auth_data(mipv6_binding_context_t *ctx)
{
	struct rr_auth_data *auth_data;

	auth_data = allocate_object(struct rr_auth_data);
	if (auth_data == NULL)
		return NULL;

	auth_data->flags = 0;
	auth_data->pending_coa = NULL;
	memset(&auth_data->kbm, 0, sizeof(struct rr_kbm));

	rr_init_single_auth_data(ctx, &auth_data->home);
	rr_init_single_auth_data(ctx, &auth_data->careof);

	return mipv6_auth_data_init(&auth_data->base, ctx, &rr_auth_data_ops);
}

mipv6_responder_auth_t *
mipv6_rr_obtain_resp_auth()
{
	struct rr_resp_auth *resp = allocate_object(struct rr_resp_auth);
	if (resp == NULL)
		return NULL;

	resp->base.ops = &rr_responder_auth_ops;
	return &resp->base;
}

void
mipv6_proto_rr_init()
{
	int i;

	proto_sec_openssl_init();

	/* init nonces and nonce generation timer */
	nonces_first = RR_NUM_NONCES - 1;
	nonces_offset = mipv6_generate_rand_uint16();

	for (i = 0; i < RR_NUM_NONCES; i++)
		rr_nonce_generate(&nonces[i], nonces_offset + i);

	timer_init_with(&nonce_timer, "nonce regeneration",
			rr_nonce_timer_callback, NULL);
	timer_add(&nonce_timer, RR_NONCE_REGEN_RATE * 1000);

	/* randomize initial Kcn */
	random_pseudo_bytes(Kcn, RR_KCN_SIZE);

	rr_register_msgs(1);

	mblty_register_shutdown(&proto_sec_shutdown);
}

