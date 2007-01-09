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
#include <stdio.h>
#include <regex.h>
#include <stdarg.h>
#include <unistd.h>
#include <regex.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <mblty/base-support.h>
#include <mblty/sock-support.h>

#include <mipv6/mipv6.h>
#include <mipv6/console.h>

#define MIPV6_RCONSOLE_CLIBUF	0x10000

struct mipv6_rconsole_client {
	int sockfd;
	char outbuf[MIPV6_RCONSOLE_CLIBUF];
	int tail;
	int doomed;

	struct list_entry entry;
};

extern const char *mipv6_console_path;
extern struct mipv6_console_cmd mipv6_console_cmds[];

static int mipv6_rconsole_sockfd = -1;
static LIST_DEF(clients);
static regex_t *compiled_commands;

static struct mipv6_rconsole_client *
mipv6_rconsole_get_client(int fd)
{
	struct mipv6_rconsole_client *cli = NULL;

	list_for_each_entry (cli, &clients, entry) {
		if (cli->sockfd == fd)
			break;
	}

	return cli;
}

void
mipv6_rconsole_remove_client(struct mipv6_rconsole_client *cli)
{
	if (cli->tail > 0) {
		cli->doomed = 1;
		return;
	}

	support_unregister_socket(cli->sockfd);
	close(cli->sockfd);
	list_del(&cli->entry);
	free_object(cli);
}

int
mipv6_rconsole_exit(struct mipv6_rconsole_client *cli)
{
	return -1;
}

static void
mipv6_rconsole_send_client(struct mipv6_rconsole_client *cli, const char *str,
			   int len)
{
	if ((cli->tail + len) > MIPV6_RCONSOLE_CLIBUF)
		return;

	memcpy(cli->outbuf + cli->tail, str, len);

	if (cli->tail == 0)
		support_get_socket(cli->sockfd)->mode |= SUPSOCKET_WRITE;

	cli->tail += len;
}

static void
mipv6_rconsole_write_client(struct mipv6_rconsole_client *cli, const char *str)
{
	mipv6_rconsole_send_client(cli, str, strlen(str));
}

void
con_printf(struct mipv6_rconsole_client *cli, const char *fmt, ...)
{
	char buf[256];
	va_list vl;
	int res;

	va_start(vl, fmt);
	res = vsnprintf(buf, sizeof(buf), fmt, vl);
	va_end(vl);

	mipv6_rconsole_send_client(cli, buf, res);
}

static int
mipv6_rconsole_client_run_cmd(struct mipv6_rconsole_client *cli,
			      const char *strp)
{
	int i;

	for (i = 0; mipv6_console_cmds[i].regex; i++) {
		if (regexec(&compiled_commands[i], strp, 0, NULL, 0) == 0) {
			if (mipv6_console_cmds[i].cmd_cb(cli) < 0) {
				mipv6_rconsole_remove_client(cli);
				return -1;
			}

			return 0;
		}
	}

	mipv6_rconsole_write_client(cli, "Unknown command.\n");
	mipv6_rconsole_remove_client(cli);

	return -1;
}

static char buf[4096];

static int
rconsole_read_ready(supsocket_t *sock)
{
	struct mipv6_rconsole_client *cli;
	char *linep, *lp;
	int res;

	cli = mipv6_rconsole_get_client(sock->fd);
	if (cli == NULL)
		return 0;

	res = recv(sock->fd, buf, sizeof(buf), MSG_DONTWAIT);
	if (res <= 0) {
		if (res == 0 || errno != EAGAIN)
			mipv6_rconsole_remove_client(cli);
		return -1;
	}

	linep = buf;
	while (1) {
		lp = strsep(&linep, "\n");
		if (lp == NULL)
			break;
		if (mipv6_rconsole_client_run_cmd(cli, lp) < 0)
			return -1;
	}

	return 0;
}

static int
rconsole_write_ready(supsocket_t *sock)
{
	struct mipv6_rconsole_client *cli;
	int res;

	cli = mipv6_rconsole_get_client(sock->fd);
	if (cli == NULL)
		return 0;

	res = send(sock->fd, cli->outbuf, cli->tail, MSG_DONTWAIT);
	if (res < 0) {
		if (errno != EAGAIN)
			mipv6_rconsole_remove_client(cli);
		return -1;
	}

	memmove(cli->outbuf, cli->outbuf + res, cli->tail - res);
	cli->tail -= res;

	if (cli->tail == 0) {
		sock->mode &= ~SUPSOCKET_WRITE;

		if (cli->doomed) {
			mipv6_rconsole_remove_client(cli);
		}
	}

	return 0;
}

static int
rconsole_connecting_waiting(supsocket_t *sock)
{
	struct mipv6_rconsole_client *cli;
	supsocket_t *newsock;
	struct sockaddr_un from;
	socklen_t fromlen;
	int newsockfd;

	memset(&from, 0, sizeof(from));
	from.sun_family = AF_UNIX;
	fromlen = sizeof(from);

	newsockfd = accept(sock->fd, (struct sockaddr *)&from, &fromlen);
	if (newsockfd < 0)
		return 0;

	cli = allocate_object(struct mipv6_rconsole_client);
	if (cli == NULL) {
		close(newsockfd);
		return 0;
	}

	cli->sockfd = newsockfd;
	cli->tail = 0;
	cli->doomed = 0;

	newsock = support_register_socket(newsockfd, rconsole_read_ready,
					  rconsole_write_ready, NULL);

	newsock->mode = SUPSOCKET_READ;

	list_add_tail(&cli->entry, &clients);

	return 0;
}

static void mipv6_rconsole_shutdown();
static struct mblty_shutdown_entry rconsole_shutdown = {
	.handler = mipv6_rconsole_shutdown,
};

void
mipv6_rconsole_init()
{
	struct sockaddr_un local;
	supsocket_t *sock;
	int i, count = 0;

	for (i = 0; mipv6_console_cmds[i].regex; i++)
		count++;

	compiled_commands = malloc(count * sizeof(regex_t));
	debug_assert(compiled_commands, "Failed to allocate regex commands.");

	for (i = 0; mipv6_console_cmds[i].regex; i++) {
		debug_assert(
			regcomp(&compiled_commands[i],
				mipv6_console_cmds[i].regex,
				REG_EXTENDED | REG_NOSUB) == 0,
			"Invalid regular expression");
	}

	mblty_register_shutdown(&rconsole_shutdown);

	mipv6_rconsole_sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (mipv6_rconsole_sockfd < 0)
		perform_shutdown("Failed to allocate rconsole socket");

	unlink(mipv6_console_path);
	memset(&local, 0, sizeof(local));
	local.sun_family = AF_UNIX;
	strcpy(local.sun_path, mipv6_console_path);

	if (bind(mipv6_rconsole_sockfd, (struct sockaddr *)&local,
		 sizeof(struct sockaddr_un)) < 0)
		perform_shutdown("Failed to bind rconsole socket");

	if (listen(mipv6_rconsole_sockfd, 5) < 0)
		perform_shutdown("Failed to start rconsole client queue");

	sock = support_register_socket(mipv6_rconsole_sockfd,
				       rconsole_connecting_waiting,
				       NULL, NULL);

	sock->mode = SUPSOCKET_READ;
}

void
mipv6_rconsole_shutdown()
{
	int i;

	if (mipv6_rconsole_sockfd >= 0) {
		support_unregister_socket(mipv6_rconsole_sockfd);
		close(mipv6_rconsole_sockfd);
		unlink(mipv6_console_path);
	}

	for (i = 0; mipv6_console_cmds[i].regex; i++) {
		regfree(&compiled_commands[i]);
	}

	free(compiled_commands);
}

