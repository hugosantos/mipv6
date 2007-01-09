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

#include <sys/un.h>
#include <unistd.h>

#include <mblty/debug.h>
#include <mblty/sock-support.h>

#include <mipv6/protocol.h>
#include <mipv6/proto-sec.h>

#define ADMINSOCK_PATH	"/var/run/racoon.sock"

#define ADMIN_DELETE_SA			0x0201
#define ADMIN_REQ_STICKY		0x1000
#define ADMIN_ESTABLISH_SA_INDIR	0x1202
#define ADMIN_UPDATE_SA_INDIR		0x1210
#define ADMIN_NOTIFY_PH1_ESTABLISHED	0x1211

#define ADMIN_PROTO_ISAKMP		0x01ff

struct admin_com {
	uint16_t ac_len;
	uint16_t ac_cmd;
	uint16_t ac_errno;
	uint16_t ac_proto;
};

struct admin_com_indexes {
	uint8_t prefs;
	uint8_t prefd;
	uint8_t proto;
	uint8_t reserved;
	struct sockaddr_storage src;
	struct sockaddr_storage dst;
};

struct admin_com_indexes_indir {
	struct admin_com_indexes idxs;
	struct sockaddr_storage indir;
};

struct racoon_req {
	struct {
		struct admin_com com;
		union {
			struct admin_com_indexes indexes;
			struct admin_com_indexes_indir indir;
		} u;
	} data;

	enum {
		RACOON_REQ_ST_UNKNOWN,
		RACOON_REQ_ST_WAITING,
	} state;

	struct list_entry entry;
};

#define MAXLEN	(sizeof(struct admin_com) + \
			sizeof(struct admin_com_indexes_indir))

static supsocket_t *racoon_sock;
static int racoon_ready = 0;

static LIST_DEF(requests);

static void racoon_update_sa(mipv6_binding_context_t *, mblty_address_t *);

static struct mipv6_ipsec_dyn_ops racoon_dyn_ops = {
	.update = racoon_update_sa,
};

void ikev1_racoon_init();

static void set_addr(struct sockaddr_storage *ss, struct in6_addr *addr)
{
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;

	sin6->sin6_family = AF_INET6;
	in6_addr_copy(&sin6->sin6_addr, addr);
}

static int
racoon_queue_request(uint16_t cmd, struct in6_addr *src, struct in6_addr *dst,
		     struct in6_addr *indirsrc)
{
	struct racoon_req *req = allocate_object(struct racoon_req);
	struct admin_com_indexes_indir *indir;
	struct admin_com_indexes *indx;
	struct admin_com *com;

	if (req == NULL)
		return -1;

	req->state = RACOON_REQ_ST_UNKNOWN;

	com = &req->data.com;
	indx = &req->data.u.indexes;
	indir = &req->data.u.indir;

	com->ac_len = sizeof(req->data);
	com->ac_cmd = cmd;
	com->ac_errno = 0;
	com->ac_proto = ADMIN_PROTO_ISAKMP;

	memset(indx, 0, sizeof(struct admin_com_indexes));

	if (src)
		set_addr(&indx->src, src);
	if (dst)
		set_addr(&indx->dst, dst);

	if (indirsrc)
		set_addr(&indir->indir, indirsrc);
	else
		memset(&indir->indir, 0, sizeof(indir->indir));

	list_add_tail(&req->entry, &requests);

	return 0;
}

static void
racoon_advance_reqs()
{
	struct racoon_req *req;

	if (!racoon_ready)
		return;

	if (list_empty(&requests))
		return;

	req = list_head(&requests, struct racoon_req, entry);
	if (req->state == RACOON_REQ_ST_WAITING)
		return;

	if (send(racoon_sock->fd, &req->data, sizeof(req->data), 0) < 0) {
		/* XXX failed */
	} else {
		req->state = RACOON_REQ_ST_WAITING;
	}
}

static void
racoon_update_sa(mipv6_binding_context_t *ctx, mblty_address_t *new_coa)
{
	struct in6_addr *hoa = mblty_get_addr(ctx->hoa);

	if (racoon_queue_request(ADMIN_UPDATE_SA_INDIR, hoa, ctx->destination,
				 &new_coa->address) < 0) {
		/* XXX failed */
		return;
	}

	racoon_advance_reqs();
}

static int
racoon_waiting(supsocket_t *sock)
{
	struct admin_com *com;
	uint8_t buf[MAXLEN];
	int len;

	com = (struct admin_com *)buf;

	len = recv(sock->fd, buf, sizeof(buf), MSG_PEEK);
	if (len == 0)
		perform_shutdown("Connection lost with Racoon");

	if (len < (int)sizeof(struct admin_com))
		return 0;

	if (len < com->ac_len)
		return 0;

	debug_log(5, "[Racoon] cmd=%i len=%i\n", (int)com->ac_cmd,
		  (int)com->ac_len);

	switch (com->ac_cmd) {
	case ADMIN_DELETE_SA:
		break;

	case ADMIN_REQ_STICKY:
		if (com->ac_errno == 0)
			racoon_ready = 1;
		else
			perform_shutdown("Failed to attach to Racoon");
		break;

	case ADMIN_ESTABLISH_SA_INDIR:
		break;

	case ADMIN_UPDATE_SA_INDIR:
		break;

	case ADMIN_NOTIFY_PH1_ESTABLISHED:
		break;

	default:
		/* We might have possibly de-synced with racoon
		 * if it is sending unknown messages. consider
		 * discarding all here */
		return 0;
	}

	return 0;
}

static void
ikev1_racoon_shutdown()
{
	int fd = racoon_sock->fd;

	support_unregister_socket(fd);
	close(fd);
}

static struct mblty_shutdown_entry racoon_shutdown = {
	.handler = ikev1_racoon_shutdown,
};

void
ikev1_racoon_init()
{
	struct sockaddr_un dst;
	int fd;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		perform_shutdown("Failed to create UNIX socket");

	memset(&dst, 0, sizeof(dst));
	dst.sun_family = AF_UNIX;
	strcpy(dst.sun_path, ADMINSOCK_PATH);

	if (connect(fd, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
		close(fd);
		perform_shutdown("Failed to connect to Racoon");
	}

	racoon_sock = support_register_socket(fd, racoon_waiting, NULL, NULL);
	racoon_sock->mode = SUPSOCKET_READ;

	mblty_register_shutdown(&racoon_shutdown);

	racoon_queue_request(ADMIN_REQ_STICKY, NULL, NULL, NULL);
}

