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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>

#include <mblty/interface.h>
#include <mblty/base-support.h>
#include <mblty/sock-support.h>

#include <mipv6/mipv6.h>
#include <mipv6/mn-hoa.h>
#include <mipv6/mn-helper.h>

#include <net/if_arp.h> /* for ARPHRD_ETHER */

void mipv6_helper_init();
void mipv6_mn_ask_helper_new_interface(mblty_os_intf_t *osh);
void mipv6_mn_ask_helper_ro(struct in6_addr *, struct in6_addr *);

static int helper_fd = -1;

static enum {
	LISTENING,
	WITH_PEER,
} helper_status;

static void mipv6_helper_resetup_listener();
static void mipv6_helper_setup_listener();

extern struct mblty_interface *mipv6_mn_found_new_interface(int, int);

static void
helper_post_question(struct mipv6_mn_helper_cmd *c, int length)
{
	if (send(helper_fd, c, length, 0) < length) {
		debug_log(1, "Failed to post question to controller.\n");
		mipv6_helper_setup_listener();
	}
}

void
mipv6_mn_ask_helper_new_interface(mblty_os_intf_t *osh)
{
	struct mipv6_mn_helper_cmd c;

	memset(&c, 0, sizeof(c));

	if (mblty_os_intf_get_type(osh) != ARPHRD_ETHER)
		return;

	if (helper_status == LISTENING) {
		debug_log(1, "No controller connected to decide if we "
			     "should use %s.\n", osh->name);
		return;
	}

	c.command = MN_H_CMD_ADDINTF;
	c.type = 0;
	strncpy(c.u.intfname, osh->name, IFNAMSIZ);

	helper_post_question(&c, sizeof(c));
}

static void
helper_do_ro(struct in6_addr *local, struct in6_addr *remote)
{
	struct mipv6_mn_hoa *hoa = mipv6_mn_get_hoa(local);
	struct mipv6_mn_individual *ind;

	if (hoa == NULL)
		return;

	ind = mipv6_mn_hoa_get_individual(hoa, remote);
	if (ind == NULL) {
		ind = mipv6_mn_hoa_alloc_individual(hoa, remote);
		if (ind == NULL)
			return;
	}

	mipv6_mn_unlock_individual(ind);
}

void
mipv6_mn_ask_helper_ro(struct in6_addr *local, struct in6_addr *remote)
{
	struct mipv6_mn_helper_cmd c;

	memset(&c, 0, sizeof(c));

	if (helper_status == LISTENING) {
		debug_log(1, "No controller connected to decide if RO should"
			     " be done, assuming yes.\n");
		helper_do_ro(local, remote);
		return;
	}

	c.command = MN_H_CMD_RO;
	c.type = 0;
	in6_addr_copy(&c.u.ro.local, local);
	in6_addr_copy(&c.u.ro.remote, remote);

	helper_post_question(&c, sizeof(c));
}

static void
mipv6_helper_handle_command(struct mipv6_mn_helper_cmd *c)
{
	if (c->command == MN_H_CMD_ADDINTF) {
		mblty_interface_t *intf;
		mblty_os_intf_t *osh =
			mblty_os_intf_get_by_name(c->u.intfname);

		if (osh == NULL)
			return;

		intf = mblty_create_interface(osh, 0, 0);
		if (intf)
			mblty_os_intf_set_up(osh, 1);
	} else if (c->command == MN_H_CMD_RO) {
		helper_do_ro(&c->u.ro.local, &c->u.ro.remote);
	}
}

static int
mipv6_helper_receive_command(supsocket_t *sock)
{
	struct mipv6_mn_helper_cmd c;
	int res;

	res = recv(sock->fd, &c, sizeof(c), 0);
	if (res <= 0) {
		mipv6_helper_resetup_listener();
		return -1;
	}

	if (res != sizeof(c))
		return 0;

	mipv6_helper_handle_command(&c);

	return 0;
}

static int
mipv6_helper_new_controller(supsocket_t *sock)
{
	supsocket_t *newsock;
	struct sockaddr_un from;
	socklen_t fromlen = sizeof(from);
	int sockfd;

	sockfd = accept(helper_fd, (struct sockaddr *)&from, &fromlen);

	support_unregister_socket(helper_fd);
	close(helper_fd);

	newsock = support_register_socket(sockfd, mipv6_helper_receive_command,
					  NULL, NULL);
	newsock->mode = SUPSOCKET_READ;

	helper_fd = sockfd;
	helper_status = WITH_PEER;

	return 0;
}

static void
mipv6_helper_resetup_listener()
{
	support_unregister_socket(helper_fd);
	close(helper_fd);

	mipv6_helper_setup_listener();
}

static void
mipv6_helper_setup_listener()
{
	struct sockaddr_un local;
	supsocket_t *sock;

	helper_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (helper_fd < 0) {
		perror("Failed to create helper socket");
		abort();
	}

	unlink("/var/run/mipv6-mn-helper");

	memset(&local, 0, sizeof(local));
	local.sun_family = AF_UNIX;
	strcpy(local.sun_path, "/var/run/mipv6-mn-helper");

	if (bind(helper_fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
		perror("Failed to bind helper socket");
		abort();
	}

	if (listen(helper_fd, 5) < 0) {
		perror("Failed to listen");
		abort();
	}

	debug_log(1, "Now listening for helper controllers.\n");

	sock = support_register_socket(helper_fd, mipv6_helper_new_controller,
				       NULL, NULL);
	sock->mode = SUPSOCKET_READ;

	helper_status = LISTENING;
}

static void mipv6_helper_shutdown();
static struct mblty_shutdown_entry helper_shutdown = {
	.handler = mipv6_helper_shutdown,
};

void
mipv6_helper_init()
{
	mblty_register_shutdown(&helper_shutdown);
	mipv6_helper_setup_listener();
}

static void
mipv6_helper_shutdown()
{
	if (helper_fd != -1) {
		support_unregister_socket(helper_fd);
		close(helper_fd);
		helper_fd = -1;
	}
}

