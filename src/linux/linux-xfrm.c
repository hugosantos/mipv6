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

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <mblty/ipsec.h>
#include <mblty/base-support.h>
#include <mblty/sock-support.h>

#include <linux/xfrm.h>

#include <netlink/msg.h>
#include <netlink/attr.h>
#include <netlink/netlink.h>

#include <mipv6/mipv6.h>

static struct nl_handle *nl_xfrm;

static LIST_DEF(policies);

static void
set_policy_seq(struct ipsec_policy *p, uint32_t seq)
{
	debug_log(0, "set_policy_seq(%p, %u)\n", p, seq);

	p->sequence = seq;
}

static void
xfrm_copy_addr(xfrm_address_t *t, struct in6_addr *addr)
{
	in6_addr_copy((struct in6_addr *)t, addr);
}

static void
xfrm_fill_selector(struct xfrm_selector *sel, struct in6_addr *src,
		   struct in6_addr *dst, int proto)
{
	memset(sel, 0, sizeof(struct xfrm_selector));

	sel->family = AF_INET6;

	xfrm_copy_addr(&sel->saddr, src);
	sel->prefixlen_s = 128;

	xfrm_copy_addr(&sel->daddr, dst);
	sel->prefixlen_d = 128;

	sel->proto = proto;
}

static int
xfrm_direction(int dir)
{
	return dir ? XFRM_POLICY_OUT : XFRM_POLICY_IN;
}

static void
xfrm_policy_addmod(int cmd, struct ipsec_policy *p)
{
	struct xfrm_userpolicy_info usinfo;
	struct xfrm_user_tmpl tmpl;
	struct nl_msg *msg;
	int res;

	msg = nlmsg_build_simple(cmd, 0);
	debug_assert(msg, "Failed to allocate XFRM message");

	memset(&usinfo, 0, sizeof(usinfo));
	memset(&tmpl, 0, sizeof(tmpl));

	usinfo.lft.soft_byte_limit = XFRM_INF;
	usinfo.lft.hard_byte_limit = XFRM_INF;
	usinfo.lft.soft_packet_limit = XFRM_INF;
	usinfo.lft.hard_packet_limit = XFRM_INF;

	usinfo.dir = xfrm_direction(p->direction);
	usinfo.action = XFRM_POLICY_ALLOW;

	xfrm_fill_selector(&usinfo.sel, p->source, p->destination,
			   p->proto);

	tmpl.family = AF_INET6;
	tmpl.aalgos = ~0;
	tmpl.ealgos = ~0;
	tmpl.calgos = ~0;

	tmpl.mode = p->ipsec_mode;
	tmpl.optional = p->ipsec_optional;

	tmpl.id.proto = p->ipsec_proto;
	tmpl.id.spi = htonl(p->spi);

	nlmsg_append(msg, &usinfo, sizeof(usinfo), 1);

	NLA_PUT(msg, XFRMA_TMPL, sizeof(tmpl), &tmpl);

	res = nl_send_auto_complete(nl_xfrm, msg);
	debug_log(0, " xfrm after send res = %i (%i, %i)\n", res,
		  sizeof(usinfo), sizeof(tmpl));

	set_policy_seq(p, nlmsg_hdr(msg)->nlmsg_seq);

nla_put_failure:
	nlmsg_free(msg);
}

static void
xfrm_policy_delget(int cmd, struct ipsec_policy *p)
{
	struct xfrm_userpolicy_id usid;
	struct nl_msg *msg;
	int res;

	msg = nlmsg_build_simple(cmd, 0);
	debug_assert(msg, "Failed to allocate XFRM message");

	memset(&usid, 0, sizeof(usid));

	usid.dir = xfrm_direction(p->direction);

	xfrm_fill_selector(&usid.sel, p->source, p->destination,
			   p->proto);

	nlmsg_append(msg, &usid, sizeof(usid), 1);

	res = nl_send_auto_complete(nl_xfrm, msg);
	debug_log(0, " xfrm get after send res = %i\n", res);

	set_policy_seq(p, nlmsg_hdr(msg)->nlmsg_seq);

	nlmsg_free(msg);
}

static void
xfrm_policy_add(struct ipsec_policy *p)
{
	xfrm_policy_addmod(XFRM_MSG_NEWPOLICY, p);
}

static void
xfrm_policy_get(struct ipsec_policy *p)
{
	xfrm_policy_delget(XFRM_MSG_GETPOLICY, p);
}

static void
xfrm_policy_del(struct ipsec_policy *p)
{
	xfrm_policy_delget(XFRM_MSG_DELPOLICY, p);
}

static void
ipsec_policy_is_now_valid(struct ipsec_policy *p)
{
	p->state = IPSEC_POLS_VALID;

	if (p->is_valid)
		p->is_valid(p);
}

static void
ipsec_handle_policy_ack(struct ipsec_policy *p, int error)
{
	if (p->state == IPSEC_POLS_ASKING) {
		if (error == -ENOENT) {
			p->state = IPSEC_POLS_INSTALLING;
			xfrm_policy_add(p);
		} else if (error == 0) {
			ipsec_policy_is_now_valid(p);
		}
	} else if (p->state == IPSEC_POLS_INSTALLING) {
		if (error == 0) {
			ipsec_policy_is_now_valid(p);
		}
	}
}

void
ipsec_require_policy(struct ipsec_policy *p)
{
	p->state = IPSEC_POLS_ASKING;
	list_add(&p->entry, &policies);

	xfrm_policy_get(p);
}

void
ipsec_release_policy(struct ipsec_policy *p)
{
	list_del(&p->entry);

	if (p->state >= IPSEC_POLS_INSTALLING) {
		xfrm_policy_del(p);
	}

	p->state = IPSEC_POLS_UNKNOWN;
}

static void
fill_ipsec_pol(struct ipsec_policy *p, int dir, struct in6_addr *src,
	       struct in6_addr *dst, uint32_t spi, int proto,
	       int ipsec_mode, int ipsec_proto, int ipsec_optional)
{
	p->direction = dir;
	p->source = src;
	p->destination = dst;
	p->spi = spi;
	p->proto = proto;
	p->ipsec_mode = ipsec_mode;
	p->ipsec_proto = ipsec_proto;
	p->ipsec_optional = ipsec_optional;
	p->owner = NULL;
	p->is_valid = NULL;
}

static void
single_ipsec_policy_is_valid(struct ipsec_policy *p)
{
	struct ipsec_bidir_policy *par = p->owner;

	if (   par->in.state == IPSEC_POLS_VALID
	    && par->out.state == IPSEC_POLS_VALID) {
		par->are_valid(par);
	}
}

void
ipsec_prepare_bidir_pol(struct ipsec_bidir_policy *p, struct in6_addr *src,
			struct in6_addr *dst, uint32_t spi, int proto,
			int ipsec_mode, int ipsec_proto, int ipsec_optional)
{
	fill_ipsec_pol(&p->out, 1, src, dst, spi, proto, ipsec_mode,
		       ipsec_proto, ipsec_optional);
	p->out.owner = p;
	p->out.is_valid = single_ipsec_policy_is_valid;
	fill_ipsec_pol(&p->in, 0, dst, src, spi, proto, ipsec_mode,
		       ipsec_proto, ipsec_optional);
	p->in.owner = p;
	p->in.is_valid = single_ipsec_policy_is_valid;

	p->owner = NULL;
	p->are_valid = NULL;
}

void
ipsec_require_bidir_pol(struct ipsec_bidir_policy *p)
{
	ipsec_require_policy(&p->out);
	ipsec_require_policy(&p->in);
}

void
ipsec_release_bidir_pol(struct ipsec_bidir_policy *p)
{
	ipsec_release_policy(&p->out);
	ipsec_release_policy(&p->in);
}

static struct ipsec_policy *
ipsec_get_policy_by_seq(uint32_t sequence)
{
	struct ipsec_policy *iter;

	list_for_each_entry (iter, &policies, entry) {
		if (   iter->state == IPSEC_POLS_INSTALLING
		    || iter->state == IPSEC_POLS_ASKING) {
			if (iter->sequence == sequence)
				return iter;
		}
	}

	return NULL;
}

static int
xfrm_nl_message(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *hdr = nlmsg_hdr(msg);

	debug_log(0, "xfrm_nl_message(%i, %i, %i)\n", (int)hdr->nlmsg_pid,
		  hdr->nlmsg_seq, hdr->nlmsg_type);

	return NL_PROCEED;
}

static void
xfrm_handle_error(uint32_t seq, int error)
{
	struct ipsec_policy *p = ipsec_get_policy_by_seq(seq);

	debug_log(0, "handle_error(%u, %i) p = %p\n", seq, error, p);

	if (p)
		ipsec_handle_policy_ack(p, error);
}

static int
xfrm_nl_ack(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *hdr = nlmsg_hdr(msg);
	int error = 0;

	debug_log(0, "xfrm_nl_ack(%i, %i, %i)\n", (int)hdr->nlmsg_pid,
		  hdr->nlmsg_seq, hdr->nlmsg_type);

	if (hdr->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *e = nlmsg_data(hdr);
		error = e->error;
	}

	xfrm_handle_error(hdr->nlmsg_seq, error);

	return NL_PROCEED;
}

static int
xfrm_nl_error(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg)
{
	xfrm_handle_error(err->msg.nlmsg_seq, err->error);

	return NL_PROCEED;
}

static int
nl_xfrm_waiting(supsocket_t *sock)
{
	nl_recvmsgs_def(nl_xfrm);
	return 0;
}

static void ipsec_shutdown();
static struct mblty_shutdown_entry shutdown_entry = {
	.handler = ipsec_shutdown,
};

void
ipsec_init()
{
	supsocket_t *sock;

	nl_xfrm = nl_handle_alloc();
	if (nl_xfrm == NULL)
		perform_shutdown(NULL, "Failed to allocate NL handle");

	mblty_register_shutdown(&shutdown_entry);

	nl_disable_sequence_check(nl_xfrm);

	/* handle normal messages */
	nl_cb_set(nl_handle_get_cb(nl_xfrm), NL_CB_VALID, NL_CB_CUSTOM,
		  xfrm_nl_message, NULL);
	/* handle ACKs */
	nl_cb_set(nl_handle_get_cb(nl_xfrm), NL_CB_ACK, NL_CB_CUSTOM,
		  xfrm_nl_ack, NULL);
	/* nl_join_groups(nl_xfrm, ~0); */

	nl_cb_err(nl_handle_get_cb(nl_xfrm), NL_CB_CUSTOM,
		  xfrm_nl_error, NULL);

	if (nl_connect(nl_xfrm, NETLINK_XFRM) < 0)
		perform_shutdown(NULL, "Failed to establish a connection with Netlink XFRM");

	fcntl(nl_handle_get_fd(nl_xfrm), F_SETFL, O_NONBLOCK);

	sock = support_register_socket(nl_handle_get_fd(nl_xfrm),
				       nl_xfrm_waiting, NULL, NULL);

	sock->mode = SUPSOCKET_READ;
}

static void
ipsec_shutdown()
{
	support_unregister_socket(nl_handle_get_fd(nl_xfrm));

	nl_close(nl_xfrm);
	nl_handle_destroy(nl_xfrm);
	nl_xfrm = NULL;
}

