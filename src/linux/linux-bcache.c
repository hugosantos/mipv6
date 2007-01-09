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
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <mblty/debug.h>
#include <mblty/sock-support.h>

#include <mipv6/os.h>
#include <mipv6/mipv6.h>
#include <mipv6/protocol.h>

#include <netlink-local.h>
#include <netlink/msg.h>
#include <netlink/netlink.h>

struct ip6_bcache_update {
	int dir;
	struct in6_addr local;
	struct in6_addr remote;
	struct in6_addr coa;
};

struct ip6_bcache_stats {
	struct in6_addr local;
	struct in6_addr remote;
	uint32_t value;
};

#define NETLINK_IP6MBLTY	23

enum {
	IP6MBLTY_NL_MSG_BCACHE_MISS = 0x10,
};

struct ip6_bcache_miss {
	struct in6_addr local;
	struct in6_addr remote;
};

#define IPV6_BCACHE_UPDATE	85
#define IPV6_BCACHE_CLEAR	87
#define IPV6_BCACHE_GET_STAT	88

extern supsocket_t *mipv6_sock;

static struct nl_handle *nl_bcache;

int
kern_bcache_update(struct in6_addr *local, struct in6_addr *remote,
		   int direction, struct in6_addr *indirection,
		   void (*cb)(void *), void *argument)
{
	char buf1[INET6_ADDRSTRLEN], buf2[INET6_ADDRSTRLEN],
	     buf3[INET6_ADDRSTRLEN];
	struct ip6_bcache_update upd;

	if (nl_bcache == NULL)
		return -1;

	upd.dir = direction;
	in6_addr_copy(&upd.local, local);
	in6_addr_copy(&upd.remote, remote);
	if (indirection)
		in6_addr_copy(&upd.coa, indirection);
	else
		memset(&upd.coa, 0, sizeof(struct in6_addr));

	if (setsockopt(mipv6_sock->fd, IPPROTO_IPV6, IPV6_BCACHE_UPDATE, &upd,
		       sizeof(upd)) < 0)
		return -1;

	debug_log(5, "[Binding Cache] changed %s %s -> %s via %s\n",
		  (direction == OS_BCE_DIR_LOCAL ? "Local" : "Remote"),
		  format_addr(buf1, local), format_addr(buf2, remote),
		  indirection ? format_addr(buf3, indirection) : NULL);

	if (cb)
		cb(argument);

	return 0;
}

void
kern_bcache_clear()
{
	if (nl_bcache == NULL)
		return;

	setsockopt(mipv6_sock->fd, IPPROTO_IPV6, IPV6_BCACHE_CLEAR, NULL, 0);
}

int
kern_bcache_get_stat(struct in6_addr *local, struct in6_addr *remote,
		     uint32_t *value)
{
	socklen_t stlen = sizeof(struct ip6_bcache_stats);
	struct ip6_bcache_stats st;
	int res;

	if (nl_bcache == NULL)
		return -1;

	in6_addr_copy(&st.local, local);
	in6_addr_copy(&st.remote, remote);
	st.value = 0;

	res = getsockopt(mipv6_sock->fd, IPPROTO_IPV6, IPV6_BCACHE_GET_STAT,
			 &st, &stlen);
	if (res < 0)
		return res;

	*value = st.value;
	return 0;
}

static int
nl_bcache_event(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *hdr = nlmsg_hdr(msg);

	if (hdr->nlmsg_type == IP6MBLTY_NL_MSG_BCACHE_MISS) {
		struct ip6_bcache_miss *bcmiss = nlmsg_data(hdr);

		char buf1[INET6_ADDRSTRLEN], buf2[INET6_ADDRSTRLEN];

		debug_log(6, "bcache miss event %s %s\n",
			  format_addr(buf1, &bcmiss->local),
			  format_addr(buf2, &bcmiss->remote));

		if (mipv6_proto_ops.bcache_miss)
			mipv6_proto_ops.bcache_miss(&bcmiss->local,
						    &bcmiss->remote);
	}

	return NL_PROCEED;
}

static int
nl_bcache_events_waiting(supsocket_t *sock)
{
	nl_recvmsgs_def(nl_bcache);
	return 0;
}

int
kern_bcache_init()
{
	supsocket_t *sock;

	nl_bcache = nl_handle_alloc();
	nl_disable_sequence_check(nl_bcache);
	nl_join_groups(nl_bcache, ~0);

	nl_cb_set(nl_handle_get_cb(nl_bcache), NL_CB_VALID, NL_CB_CUSTOM,
		  nl_bcache_event, NULL);

	if (nl_connect(nl_bcache, NETLINK_IP6MBLTY) < 0) {
		debug_log(1, "nl_connect(NETLINK_IP6MBLTY) failed: %s.\n",
			  strerror(errno));
		nl_close(nl_bcache);
		nl_bcache = NULL;
		return -1;
	}

	fcntl(nl_handle_get_fd(nl_bcache), F_SETFL, O_NONBLOCK);

	sock = support_register_socket(nl_handle_get_fd(nl_bcache),
				       nl_bcache_events_waiting, NULL, NULL);
	sock->mode = SUPSOCKET_READ;

	return 0;
}

void
kern_bcache_shutdown()
{
	if (nl_bcache) {
		support_unregister_socket(nl_handle_get_fd(nl_bcache));
		nl_close(nl_bcache);
		nl_handle_destroy(nl_bcache);
		nl_bcache = NULL;
	}
}

