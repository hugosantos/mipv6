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

#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <mblty/icmpv6.h>
#include <mblty/router.h>
#include <mblty/base-support.h>
#include <mblty/sock-support.h>

#include <mipv6/os.h>
#include <mipv6/mipv6.h>
#include <mipv6/protocol.h>
#include <mipv6/proto-sec.h>

extern uint16_t ip6_cksum(uint8_t proto, struct in6_addr *src,
			  struct in6_addr *dst, void *data, int len);

supsocket_t *mipv6_sock = NULL;

static uint8_t _msg_buf[2048];

static const char *_mipv6_message_names[] = {
	"BindingRefresh",
	"HomeTestInit",
	"CareOfTestInit",
	"HomeTest",
	"CareOfTest",
	"BindingUpdate",
	"BindingAcknowledge",
	"BindingError",
};

typedef void (*mipv6_mh_handler)(struct mipv6_msgctx *);

#define IP6_MH_TYPE_MAX		(IP6_MH_TYPE_BERROR + 1)

typedef mipv6_mh_handler handler_list[IP6_MH_TYPE_MAX];

static handler_list mh_handlers, mh_prob_handlers;

#define MIPV6_BERR_RL_N	10
#define MIPV6_BERR_RL_B 10
static icmpv6_rate_limit_t _berr_rl;

static const char *
_mipv6_message_name(int type) {
	if (type >= IP6_MH_TYPE_BRR && type <= IP6_MH_TYPE_BERROR) {
		return _mipv6_message_names[type];
	}

	return "Unknown";
}

struct ip6_mh_opt *
mipv6_first_opt(void *ptr, size_t length)
{
	uint8_t *data = ptr;

	if (length == 0)
		return NULL;

	if (data[0] != IP6_MHOPT_PAD1) {
		if (length < 2 || length < data[1])
			return NULL;
	}

	return (struct ip6_mh_opt *)data;
}

struct ip6_mh_opt *
mipv6_next_opt(struct ip6_mh_opt *opt, size_t *length)
{
	size_t optlen;

	if (opt->ip6mhopt_type == IP6_MHOPT_PAD1)
		optlen = 1;
	else
		optlen = opt->ip6mhopt_len + 2;

	if (*length < optlen)
		return NULL;

	(*length) -= optlen;

	return (struct ip6_mh_opt *)(((uint8_t *)opt) + optlen);
}

static void *
ip6_get_exthdr(void *data, size_t len, int type)
{
	/* ptr points to ip6_hdr */
	uint8_t *ptr = data;
	uint8_t *end = ptr + len;
	int optlen, nxthdr;

	if (len < sizeof(struct ip6_hdr))
		return NULL;

	nxthdr = ptr[6];
	ptr += sizeof(struct ip6_hdr);

	while (ptr < end) {
		if (nxthdr == type)
			return ptr;

		optlen = (ptr[1] + 1) * 8;
		if ((ptr + optlen) >= end)
			break;

		nxthdr = ptr[0];
		ptr += optlen;
	}

	return NULL;
}

static void *
build_ip6opt(uint8_t *opt, size_t *length, int type, size_t optlen)
{
	debug_assert(optlen >= 2, "Invalid optlen in build_ip6opt.");

	opt[0] = type;
	opt[1] = optlen - 2;
	(*length) += optlen;
	return opt + optlen;
}

static uint8_t *
pad_ip6opt(uint8_t *hdrstart, uint8_t *ptr, size_t *length, int x, int y)
{
	size_t padlen, diff;

	debug_assert(hdrstart <= ptr, "ptr before hdrstart?");

	diff = ptr - hdrstart;
	padlen = (((diff % x) + (x - 1)) & ~(x - 1)) - (diff % x);
	padlen += y;
	padlen %= x;

	(*length) += padlen;

	if (padlen == 1) {
		ptr[0] = IP6OPT_PAD1;
	} else if (padlen > 1) {
		ptr[0] = IP6OPT_PADN;
		ptr[1] = padlen - 2;
		memset(ptr + 2, 0, padlen - 2);
	}

	return ptr + padlen;
}

void
mipv6_build_header(struct ip6_mh *hdr, size_t size, int type)
{
	debug_assert(size >= 8 && (size % 8) == 0, "Invalid header size.");

	hdr->ip6mh_proto = IPPROTO_NONE;
	hdr->ip6mh_hdrlen = (size - 8) / 8;
	hdr->ip6mh_type = type;
	hdr->ip6mh_reserved = 0;
	hdr->ip6mh_cksum = 0;
}

const char *
mipv6_ack_status_name(int status)
{
	switch (status) {
	case IP6_MH_BAS_ACCEPTED:
		return "Accepted";
	case IP6_MH_BAS_PRFX_DISCOV:
		return "Prefix Discovery required";
	case IP6_MH_BAS_UNSPECIFIED:
		return "Unspecified";
	case IP6_MH_BAS_PROHIBIT:
		return "Administratively prohibited";
	case IP6_MH_BAS_INSUFFICIENT:
		return "Insufficient resources";
	case IP6_MH_BAS_HA_NOT_SUPPORTED:
		return "HA registration not supported";
	case IP6_MH_BAS_NOT_HOME_SUBNET:
		return "Not Home subnet";
	case IP6_MH_BAS_NOT_HA:
		return "Not an Home Agent";
	case IP6_MH_BAS_DAD_FAILED:
		return "DAD failed";
	case IP6_MH_BAS_SEQNO_BAD:
		return "Bad Sequence number";
	case IP6_MH_BAS_HOME_NI_EXPIRED:
		return "Expired Home nonce index";
	case IP6_MH_BAS_COA_NI_EXPIRED:
		return "Expired CoA nonce index";
	case IP6_MH_BAS_NI_EXPIRED:
		return "Expired Nonce indices";
	case IP6_MH_BAS_REG_NOT_ALLOWED:
		return "Registration not allowed";
	default:
		return "Unknown status";
	}
}

static void
mipv6_send_param_prob(struct mipv6_msgctx *msg, int type, int ptr)
{
	if (msg->orighdr == NULL) {
		debug_log(1, "Kernel didn't handle the original headers,"
			  " won't send ICMPv6 Param Prob with type=%i and"
			  " ptr=%i.\n", type, ptr);
		return;
	}

	icmpv6_send_param_prob(type, ptr, msg->to, msg->from, msg->orighdr,
			       msg->orighdrlen, msg->u.raw, msg->msglen);
}

int
mipv6_validate_message(struct mipv6_msgctx *msg, size_t minlen)
{
	size_t hdrlen;

	if (msg->msglen < minlen)
		return -1;

	hdrlen = (msg->u.hdr->ip6mh_hdrlen + 1) * 8;
	if (hdrlen >= minlen)
		return 0;

	mipv6_send_param_prob(msg, ICMP6_PARAMPROB_HEADER, 0);
	return -1;
}

int
mipv6_sendmsg(struct mipv6_mh_bld_ctx *msgctx,
	      struct in6_addr *src, struct in6_addr *dst,
	      struct in6_addr *indsrc, struct in6_addr *inddst)
{
	char buf1[INET6_ADDRSTRLEN], buf2[INET6_ADDRSTRLEN];
	supsocket_txopt_t txopt = SUPSOCK_EMPTY_TXOPT;
	struct ip6_mh *mh = msgctx->h.mh;
	int res;

	debug_log(5, "mipv6_sendmsg(%s, %s, %s, %i bytes)\n",
		  _mipv6_message_name(mh->ip6mh_type),
		  format_addr(buf1, dst), format_addr(buf2, src),
		  msgctx->length);

	if (src) {
		txopt.flags |= SUPSTXO_SOURCE_ADDR;

		if (indsrc) {
			txopt.flags |= SUPSTXO_SOURCE_HOA;
			txopt.src = indsrc;
			txopt.hoa = src;
		} else {
			txopt.src = src;
		}
	}

	if (inddst) {
		txopt.flags |= (SUPSTXO_DEST_INDIR_RT);
		txopt.dst = inddst;
		txopt.rttype = 2;
	}

	mh->ip6mh_cksum = ip6_cksum(IPPROTO_MH, src, dst, mh, msgctx->length);

	res = mblty_sk_send(mipv6_sock, dst, mh, msgctx->length, &txopt);
	if (res < 0) {
		debug_log(9, " >> mipv6_sendmsg failed: %s\n", strerror(errno));
	}

	return res;
}

static void
mipv6_send_binding_error(struct in6_addr *_from, struct in6_addr *_to,
			 struct in6_addr *hoa, int status)
{
	char buf1[INET6_ADDRSTRLEN], buf2[INET6_ADDRSTRLEN];
	struct ip6_mh_binding_error *bu_err;
	struct mipv6_mh_bld_ctx msgctx;

	if (IN6_IS_ADDR_UNSPECIFIED(_to) || IN6_IS_ADDR_LINKLOCAL(_to) ||
	    IN6_IS_ADDR_MULTICAST(_to))
		return;

	if (icmpv6_rate_limited(&_berr_rl))
		return;

	debug_log(2, "Sending Binding Error to %s from %s with status %i.\n",
		  format_addr(buf1, _to), format_addr(buf2, _from), status);

	bu_err = mipv6_mh_start(&msgctx, sizeof(struct ip6_mh_binding_error));

	bu_err->ip6mhbe_status = status;
	if (hoa)
		in6_addr_copy(&bu_err->ip6mhbe_homeaddr, hoa);

	mipv6_build_header(msgctx.h.mh, msgctx.length, IP6_MH_TYPE_BERROR);

	if (mipv6_sendmsg(&msgctx, _from, _to, NULL, NULL) < 0) {
		/* Failed to send */
		return;
	}

	icmpv6_rate_limit_add(&_berr_rl);
}

static void
mipv6_handle_message(struct mipv6_msgctx *ctx)
{
	char buf1[INET6_ADDRSTRLEN], buf2[INET6_ADDRSTRLEN];
	mipv6_mh_handler handler = NULL;

	if (ctx->msglen < sizeof(struct ip6_mh))
		return;

	if (ctx->u.hdr->ip6mh_proto != IPPROTO_NONE) {
		mipv6_send_param_prob(ctx, ICMP6_PARAMPROB_HEADER, 0);
		return;
	}

	debug_log(5, "mipv6_handle_message %i from %s to %s\n",
		  ctx->u.hdr->ip6mh_type, format_addr(buf1, ctx->from),
		  format_addr(buf2, ctx->to));

	if (ctx->u.hdr->ip6mh_type < IP6_MH_TYPE_MAX)
		handler = mh_handlers[ctx->u.hdr->ip6mh_type];

	if (handler)
		handler(ctx);
	else
		mipv6_send_binding_error(ctx->to, ctx->from, ctx->hoa,
					 IP6_MH_BES_UNKNOWN_MH);
}

static int
tlv_option_find(uint8_t *ptr, int len, uint8_t **dst, int type)
{
	uint8_t *end = ptr + len;
	int optlen;

	while (ptr < end) {
		optlen = ptr[1] + 2;

		if ((ptr + optlen) > end)
			return -1;
		else if (ptr[0] == type) {
			*dst = ptr;
			return 0;
		}

		ptr += optlen;
	}

	return -1;
}

static struct in6_addr *
get_dstopts_hoa_opt(void *data)
{
	uint8_t *opt, *dstopt = data;

	if (tlv_option_find(dstopt + 2, (dstopt[1] + 1) * 8, &opt,
			    IP6OPT_HOME_ADDRESS) < 0)
		return NULL;

	if (opt[1] != 16)
		return NULL;

	return (struct in6_addr *)(opt + 2);
}

static int
mipv6_message_waiting(supsocket_t *sock)
{
	char buf1[INET6_ADDRSTRLEN];
	struct mipv6_msgctx ctx;
	supsocket_rxparm_t rxp;
	int length;

	length = mblty_sk_recv(mipv6_sock, _msg_buf, sizeof(_msg_buf), &rxp);

	debug_assert(rxp.flags & SUPSRXP_RECV_INFO,
		     "Missing information from kernel.");

	ctx.u.raw = _msg_buf;
	ctx.msglen = length;

	ctx.from = rxp.src;
	ctx.to = rxp.dst;
	ctx.hoa = ctx.origdst = NULL;
	ctx.intf = rxp.intf;

	if (rxp.flags & SUPSRXP_NETWRKHDRS_INFO) {
		ctx.orighdr = rxp.ip6hdr;
		ctx.orighdrlen = rxp.ip6hdrlen;
	} else {
		ctx.orighdr = NULL;
		ctx.orighdrlen = 0;
	}

	if (rxp.flags & SUPSRXP_DSTOPS_INFO) {
		struct in6_addr *coa = get_dstopts_hoa_opt(rxp.dsthdr);

		if (coa) {
			ctx.hoa = ctx.from;
			ctx.from = coa;
		}
	}

	if (rxp.flags & SUPSRXP_RTHDR_INFO) {
		if (rxp.rthdr->ip6r_type == 2) {
			struct ip6_rthdr2 *rt2 = (struct ip6_rthdr2 *)rxp.rthdr;

			debug_log(5, "Got RT2-Hdr info (%s)\n",
				  format_addr(buf1, &rt2->ip6r2_homeaddr));
			ctx.origdst = &rt2->ip6r2_homeaddr;
		}
	}

	mipv6_handle_message(&ctx);

	return 0;
}

static void
mipv6_handle_icmpv6_param_prob(struct icmp6_hdr *hdr, int length,
			       supsocket_rxparm_t *rxp)
{
	size_t mh_len, ip6_len = length - sizeof(struct icmp6_hdr);
	struct ip6_hdr *ip6hdr = (void *)(hdr + 1);
	mipv6_msgctx_t ctx;
	struct ip6_mh *mh;
	void *dstopts;

	debug_log(4, "ICMPv6 Param Prob, ip6_len = %i\n", ip6_len);

	mh = ip6_get_exthdr(ip6hdr, ip6_len, IPPROTO_MH);
	if (mh == NULL) {
		/* too many options or not a MH, ignore */
		return;
	}

	mh_len = length - (((uint8_t *)mh) - (uint8_t *)hdr);
	if (mh_len < sizeof(struct ip6_mh))
		return;

	debug_log(4, "Got ICMPv6 Param Prob (mh_len = %i).\n", mh_len);

	ctx.from = &ip6hdr->ip6_src;
	ctx.to = &ip6hdr->ip6_dst;

	dstopts = ip6_get_exthdr(ip6hdr, ip6_len, IPPROTO_DSTOPTS);
	if (dstopts)
		ctx.hoa = get_dstopts_hoa_opt(dstopts);
	else
		ctx.hoa = NULL;

	/* XXX ignore RT2 hdr for now */
	ctx.origdst = NULL;
	ctx.intf = rxp->intf;
	ctx.u.hdr = mh;
	ctx.msglen = mh_len;
	ctx.orighdr = ip6hdr;
	ctx.orighdrlen = ip6_len - mh_len;

	if (mh->ip6mh_type >= IP6_MH_TYPE_MAX ||
	    mh_prob_handlers[mh->ip6mh_type] == NULL)
		return;

	mh_prob_handlers[mh->ip6mh_type](&ctx);
}

void *
mipv6_mh_start(struct mipv6_mh_bld_ctx *ctx, size_t mh_len)
{
	ctx->length = mh_len;
	ctx->h.raw = _msg_buf;
	ctx->mobopt = _msg_buf + mh_len;

	memset(ctx->h.raw, 0, mh_len);

	return ctx->h.raw;
}

uint8_t *
mipv6_mh_pad(struct mipv6_mh_bld_ctx *ctx, int x, int y)
{
	return pad_ip6opt(ctx->h.raw, ctx->mobopt, &ctx->length, x, y);
}

void *
mipv6_mh_add_opt(struct mipv6_mh_bld_ctx *ctx, int x, int y,
		 int type, size_t optlen)
{
	uint8_t *opt = mipv6_mh_pad(ctx, x, y);

	ctx->mobopt = build_ip6opt(opt, &ctx->length, type, optlen);

	return opt;
}

static void
mipv6_protocol_shutdown()
{
	icmpv6_register_handler(ICMP6_PARAM_PROB,
				mipv6_handle_icmpv6_param_prob, 0);

	mblty_close_socket(mipv6_sock);
	mipv6_sock = NULL;

	kern_bcache_shutdown();
}

static struct mblty_shutdown_entry protocol_shutdown = {
	.handler = mipv6_protocol_shutdown,
};

void
mipv6_protocol_init()
{
	int i;

	srand(time(NULL));

	icmpv6_rate_limit_init(&_berr_rl, MIPV6_BERR_RL_N, MIPV6_BERR_RL_B);

	mipv6_sock = mblty_create_socket(AF_INET6, SOCK_RAW, IPPROTO_MH,
					 mipv6_message_waiting, NULL, NULL);

	if (kern_bcache_init() < 0) {
		debug_log(0, "[*] No Kernel Binding Cache available. Route"
			  " Optimization capability not available.\n");
	} else {
		kern_bcache_clear();
	}

	mblty_register_shutdown(&protocol_shutdown);

	/* We ignore RECVNETWORKHDRS availability. If it isn't available,
	 * orighdr will be NULL and Parameter Problem errors won't be
	 * sent. */
	mblty_sk_enable(mipv6_sock, SUPSCAP_NETWRKHDRS_INFO);

	if (mblty_sk_enable(mipv6_sock, SUPSCAP_RTHDR_INFO) != 0 ||
	    mblty_sk_enable(mipv6_sock, SUPSCAP_RECV_INFO) != 0 ||
	    mblty_sk_enable(mipv6_sock, SUPSCAP_DSTOPTS_INFO) != 0)
		perform_shutdown("Missing kernel capabilities");

	mipv6_sock->mode = SUPSOCKET_READ;

	/* check for parameter problems in response to BUs, etc */
	icmpv6_register_handler(ICMP6_PARAM_PROB,
				mipv6_handle_icmpv6_param_prob, 1);

	for (i = 0; i < IP6_MH_TYPE_MAX; i++) {
		mh_handlers[i] = NULL;
		mh_prob_handlers[i] = NULL;
	}

	mipv6_proto_rr_init();
	mipv6_proto_mn_init();
	mipv6_proto_cn_init();
}

uint16_t
mipv6_generate_rand_uint16()
{
	return (uint16_t)(65536.0 * rand() / (RAND_MAX + 1.0));
}

static void
mipv6_generic_reg_handler(handler_list *h, int type,
			  void (*cb)(mipv6_msgctx_t *), int on)
{
	debug_assert(type < IP6_MH_TYPE_MAX, "Unsupported type");

	if (on) {
		debug_assert((*h)[type] == NULL, "Already registered");
		(*h)[type] = cb;
	} else {
		debug_assert((*h)[type] == cb, "Bad unregister");
		(*h)[type] = NULL;
	}
}

void
mipv6_proto_register_handler(int type, void (*cb)(mipv6_msgctx_t *), int on)
{
	mipv6_generic_reg_handler(&mh_handlers, type, cb, on);
}

void
mipv6_proto_register_prob_handler(int type, void (*cb)(mipv6_msgctx_t *),
				  int on)
{
	mipv6_generic_reg_handler(&mh_prob_handlers, type, cb, on);
}

mipv6_auth_data_t *
mipv6_auth_data_init(mipv6_auth_data_t *data, mipv6_binding_context_t *ctx,
		     mipv6_auth_data_ops_t *ops)
{
	data->parent = ctx;
	data->ops = ops;
	data->updated = NULL;
	data->failed = NULL;
	return data;
}

void
mipv6_auth_data_update(mipv6_binding_context_t *ctx, mblty_address_t *addr)
{
	ctx->auth->ops->update(ctx, addr);
}

void
mipv6_auth_data_cancel(mipv6_binding_context_t *ctx, mblty_address_t *addr)
{
	ctx->auth->ops->cancel(ctx, addr);
}

void
mipv6_auth_data_clear(mipv6_binding_context_t *ctx)
{
	ctx->auth->ops->clear(ctx);
}

int
mipv6_auth_data_is_valid(mipv6_binding_context_t *ctx)
{
	if (ctx->auth == NULL || ctx->auth->ops->is_valid == NULL)
		return 1;

	return ctx->auth->ops->is_valid(ctx);
}

void
mipv6_auth_data_release(mipv6_auth_data_t *auth)
{
	auth->ops->release(auth);
}

