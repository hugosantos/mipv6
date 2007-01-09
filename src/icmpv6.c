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
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include <mblty/icmpv6.h>
#include <mblty/interface.h>
#include <mblty/base-support.h>
#include <mblty/sock-support.h>

static supsocket_t *icmpv6_sock = NULL;
static uint8_t _msg_buf[2048];

/* Yay, 256 available icmpv6 types */
static icmpv6_handler _handlers[256];

#define ICMPV6_TB_N	10 /* 10/s */
#define ICMPV6_TB_B	10 /* 10 */
static icmpv6_rate_limit_t _rl;

struct mcg_record {
	mblty_os_intf_t *intf;
	struct in6_addr address;
	int refcount;
	struct list_entry entry;
};

static LIST_DEF(mcg_records);

icmpv6_handler
icmpv6_register_handler(int type, icmpv6_handler handler, int on)
{
	icmpv6_handler old = _handlers[type];

	if (on) {
		_handlers[type] = handler;
	} else {
		_handlers[type] = NULL;
	}

	return old;
}

static struct mcg_record *
mcg_obtain_record(mblty_os_intf_t *osh, struct in6_addr *grpaddr)
{
	struct mcg_record *iter;

	list_for_each_entry (iter, &mcg_records, entry) {
		if (iter->intf == osh &&
		    in6_addr_compare(&iter->address, grpaddr) == 0)
			return iter;
	}

	return NULL;
}

int
icmpv6_join_mc(mblty_os_intf_t *intf, struct in6_addr *grp)
{
	char buf1[INET6_ADDRSTRLEN], descbuf[64];
	struct mcg_record *rec;

	debug_log(4, "  icmpv6_join_mc(%s, %s)\n",
		  mblty_os_intf_desc(intf, 1, descbuf, sizeof(descbuf)),
		  format_addr(buf1, grp));

	rec = mcg_obtain_record(intf, grp);
	if (rec == NULL) {
		rec = allocate_object(struct mcg_record);
		if (rec == NULL)
			return -1;

		if (mblty_sk_join_mc(icmpv6_sock, intf, grp) < 0) {
			free_object(rec);
			return -1;
		}

		rec->intf = intf;
		in6_addr_copy(&rec->address, grp);
		list_add_tail(&rec->entry, &mcg_records);
		rec->refcount = 0;
	}

	rec->refcount++;

	return 0;
}

int
icmpv6_leave_mc(mblty_os_intf_t *intf, struct in6_addr *grp)
{
	char buf1[INET6_ADDRSTRLEN], descbuf[64];
	struct mcg_record *rec;

	debug_log(4, "  icmpv6_leave_mc(%s, %s)\n",
		  mblty_os_intf_desc(intf, 1, descbuf, sizeof(descbuf)),
		  format_addr(buf1, grp));

	rec = mcg_obtain_record(intf, grp);
	if (rec == NULL)
		return -1;

	rec->refcount--;
	if (rec->refcount == 0) {
		list_del(&rec->entry);
		free_object(rec);
		mblty_sk_leave_mc(icmpv6_sock, intf, grp);
	}

	return 0;
}

int
icmpv6_sk_enable(supsocket_cap_t cap)
{
	return mblty_sk_enable(icmpv6_sock, cap);
}

int
icmpv6_sk_disable(supsocket_cap_t cap)
{
	return mblty_sk_enable(icmpv6_sock, cap);
}

int
icmpv6_send(struct in6_addr *to, struct in6_addr *from, mblty_os_intf_t *intf,
	    int hoplimit, struct icmp6_hdr *hdr, int len)
{
	char buf1[INET6_ADDRSTRLEN], buf2[INET6_ADDRSTRLEN];
	supsocket_txopt_t opt = SUPSOCK_EMPTY_TXOPT;
	int res;

	if (IN6_IS_ADDR_LINKLOCAL(to) ||
	    IN6_IS_ADDR_MC_LINKLOCAL(to)) {
		debug_assert(from, "Source address not specified for link-"
			     "local ICMPv6 sendmsg.");
	}

	debug_log(5, "    icmpv6_send(%s, %s, %i bytes)\n",
		  format_addr(buf1, to), format_addr(buf2, from), len);

	if (from) {
		opt.flags |= SUPSTXO_SOURCE_ADDR;
		opt.src = from;
	}

	if (intf) {
		opt.flags |= SUPSTXO_SOURCE_INTF;
		opt.intf = intf;
	}

	opt.hoplimit = hoplimit;

	res = mblty_sk_send(icmpv6_sock, to, hdr, len, &opt);

	if (res < 0)
		debug_log(3, "icmpv6_send failed: %s\n", strerror(errno));

	return res;
}

int
icmpv6_send_error(struct in6_addr *to, struct in6_addr *from,
		  mblty_os_intf_t *intf, int hoplimit, struct icmp6_hdr *hdr,
		  int length)
{
	int res;

	/* may we send the message? */
	if (icmpv6_rate_limited(&_rl))
		return 0;

	res = icmpv6_send(to, from, intf, hoplimit, hdr, length);
	if (res < 0)
		return res;

	icmpv6_rate_limit_add(&_rl);

	return res;
}

static int
icmpv6_message_waiting(supsocket_t *sock)
{
	struct icmp6_hdr *hdr = (struct icmp6_hdr *)_msg_buf;
	mblty_interface_t *intf;
	supsocket_rxparm_t rxp;
	int length;

	length = mblty_sk_recv(icmpv6_sock, _msg_buf, sizeof(_msg_buf), &rxp);

	debug_assert(rxp.flags & SUPSRXP_RECV_INFO,
		     "Missing information from kernel.");

	if (length < (int)sizeof(struct icmp6_hdr)) {
		/* Message too small */
		return 0;
	}

	if (_handlers[hdr->icmp6_type] == NULL)
		return 0;

	intf = mblty_get_interface(rxp.intf);
	if (intf) {
		int from_us = mblty_has_address(intf, rxp.src);
		mblty_put_interface(intf);
		if (from_us)
			return 0;
	}

	_handlers[hdr->icmp6_type](hdr, length, &rxp);

	return 0;
}

void
icmpv6_send_param_prob(int type, int ptr, struct in6_addr *from,
		       struct in6_addr *to, struct ip6_hdr *orig, int origlen,
		       void *payload, int payloadlen)
{
	struct icmp6_hdr *hdr = (struct icmp6_hdr *)_msg_buf;
	int max, totalcount;
	uint8_t *p;

	hdr->icmp6_type = ICMP6_PARAM_PROB;
	hdr->icmp6_code = type;
	hdr->icmp6_cksum = 0;
	hdr->icmp6_pptr = ptr;

	/* copy the original headers right to the beggining of the
	 * icmp payload */
	p = (uint8_t *)(hdr + 1);

	/* will try to fit as much as possible in 1280 bytes */
	max = 1280 - sizeof(struct ip6_hdr) - sizeof(struct icmp6_hdr);
	totalcount = sizeof(struct icmp6_hdr);

	if (origlen > max)
		origlen = max;
	memcpy(p, orig, origlen);
	p += origlen;
	max -= origlen;
	totalcount += origlen;

	if (max) {
		if (payloadlen > max)
			payloadlen = max;
		memcpy(p, payload, payloadlen);
		totalcount += payloadlen;
	}

	if (icmpv6_send_error(to, from, NULL, -1, hdr, totalcount) < 0) {
		debug_log(2, "failed to send icmpv6 param prob message");
	}
}

void
icmpv6_rate_limit_init(icmpv6_rate_limit_t *rl, uint32_t n, uint32_t b)
{
	rl->n = n;
	rl->b = b;
	rl->last = rl->count = rl->count = 0;
}

int
icmpv6_rate_limited(icmpv6_rate_limit_t *rl)
{
	rl->now = time(NULL);

	if (rl->last == rl->now) {
		if (rl->count >= rl->b) {
			/* message won't be sent */
			return 1;
		}
	}

	return 0;
}

void
icmpv6_rate_limit_add(icmpv6_rate_limit_t *rl)
{
	if (rl->last == rl->now) {
		rl->count++;
	} else {
		rl->count = 1;
		rl->last = rl->now;
	}
}

static void icmpv6_protocol_shutdown();
static struct mblty_shutdown_entry shutdown_entry = {
	.handler = icmpv6_protocol_shutdown,
};

void
icmpv6_protocol_init()
{
	memset(_handlers, 0, sizeof(_handlers));

	icmpv6_rate_limit_init(&_rl, ICMPV6_TB_N, ICMPV6_TB_B);

	icmpv6_sock = mblty_create_socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6,
					  icmpv6_message_waiting, NULL, NULL);
	if (icmpv6_sock == NULL)
		perform_shutdown("Failed to create ICMPv6 socket: %s",
				 strerror(errno));

	icmpv6_sock->mode = SUPSOCKET_READ;

	mblty_register_shutdown(&shutdown_entry);

	if (mblty_sk_enable(icmpv6_sock, SUPSCAP_RECV_INFO) != 0)
		perform_shutdown("Missing kernel capabilities");

	if (mblty_sk_disable(icmpv6_sock, SUPSCAP_MULTICAST_LOOP) != 0)
		perform_shutdown("Missing kernel capabilities.");
}

void
icmpv6_protocol_shutdown()
{
	mblty_close_socket(icmpv6_sock);
	icmpv6_sock = NULL;
}

