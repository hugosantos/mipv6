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
#include <stdlib.h>
#include <stdarg.h>
#include <signal.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/utsname.h>

#include <mblty/interface.h>
#include <mblty/base-support.h>
#include <mblty/sock-support.h>

/* for now we keep a static array */
#define SUPPORT_MAX_SOCKS	16
static supsocket_t _sockets[SUPPORT_MAX_SOCKS];

static LIST_DEF(shutdown_list);

struct support_debug_conf *debug_conf = NULL;
struct mblty_event_ops *mblty_global_events = NULL;

static supsocket_t *
get_free_socket()
{
	int i;

	for (i = 0; i < SUPPORT_MAX_SOCKS; i++) {
		if (_sockets[i].fd < 0)
			return &_sockets[i];
	}

	return NULL;
}

supsocket_t *
mblty_create_socket(int domain, int type, int protocol,
		    sup_socket_cb_t r_cb, sup_socket_cb_t w_cb,
		    sup_socket_cb_t e_cb)
{
	supsocket_t *sock = get_free_socket();

	if (sock == NULL)
		return NULL;

	if (os_create_socket(sock, domain, type, protocol) < 0)
		return NULL;

	sock->mode = 0;
	sock->cbs[0] = r_cb;
	sock->cbs[1] = w_cb;
	sock->cbs[2] = e_cb;

	return sock;
}

void
mblty_close_socket(supsocket_t *sock)
{
	os_close_socket(sock);
	sock->fd = -1;
}

supsocket_t *
support_register_socket(int fd, sup_socket_cb_t r_cb, sup_socket_cb_t w_cb,
			sup_socket_cb_t e_cb)
{
	supsocket_t *sock = get_free_socket();

	debug_assert(sock, "No available socket slots.");

	sock->fd = fd;
	sock->mode = 0;
	sock->cbs[0] = r_cb;
	sock->cbs[1] = w_cb;
	sock->cbs[2] = e_cb;

	return sock;
}

supsocket_t *
support_get_socket(int fd)
{
	int i;

	for (i = 0; i < SUPPORT_MAX_SOCKS; i++) {
		if (_sockets[i].fd == fd)
			return &_sockets[i];
	}

	return NULL;
}

void
support_unregister_socket(int fd)
{
	supsocket_t *sock = support_get_socket(fd);

	if (sock == NULL)
		return;

	sock->fd = -1;

	memset(sock->cbs, 0, sizeof(sock->cbs));
}

static void
support_clear_sockets()
{
	int i;

	for (i = 0; i < SUPPORT_MAX_SOCKS; i++) {
		memset(&_sockets[i], 0, sizeof(_sockets[i]));
		_sockets[i].fd = -1;
	}
}

static void
support_construct_fdset(int *maxsock, fd_set *rset, fd_set *wset)
{
	int i;

	for (i = 0; i < SUPPORT_MAX_SOCKS; i++) {
		if (_sockets[i].fd >= 0) {
			if (_sockets[i].mode & SUPSOCKET_READ)
				FD_SET(_sockets[i].fd, rset);

			if (_sockets[i].mode & SUPSOCKET_WRITE)
				FD_SET(_sockets[i].fd, wset);

			if (_sockets[i].fd > *maxsock)
				*maxsock = _sockets[i].fd;
		}
	}
}

static void
support_call_sockets(fd_set *rset, fd_set *wset)
{
	int i;

	for (i = 0; i < SUPPORT_MAX_SOCKS; i++) {
		if (_sockets[i].fd >= 0) {
			if (FD_ISSET(_sockets[i].fd, rset))
				if (_sockets[i].cbs[0](&_sockets[i]) < 0)
					continue;
			if (FD_ISSET(_sockets[i].fd, wset))
				if (_sockets[i].cbs[1](&_sockets[i]) < 0)
					continue;
		}
	}
}

void
mblty_register_shutdown(struct mblty_shutdown_entry *entry)
{
	list_add(&entry->entry, &shutdown_list);
}

void
mblty_shutdown()
{
	struct mblty_shutdown_entry *entry;

	debug_log(0, "------------- Shutting down -------------\n");

	mblty_clear_interfaces();

	while (!list_empty(&shutdown_list)) {
		entry = list_head(&shutdown_list, struct mblty_shutdown_entry,
				  entry);

		entry->handler();
		list_del(&entry->entry);
	}

	os_internal_shutdown();

	support_timers_shutdown();

	debug_close_facilities();

	exit(0);
}

static void
handle_sigc(int sig)
{
	mblty_shutdown();
}

static void
handle_sigsegv(int sig, siginfo_t *info, void *ptr)
{
	struct utsname name;

	debug_log(0, "  ________________________________________________________ \n");
	debug_log(0, "//                                                        ||\n");
	debug_log(0, "|| It seems MOBSIX has crashed. Please contact either the ||\n");
	debug_log(0, "|| package maintainer or the software authors and include ||\n");
	debug_log(0, "|| the following information in your report.              ||\n");
	debug_log(0, "||_______________________________________________________//\n");
	debug_log(0, "\n");
	debug_log(0, "--------------------- START CUT HERE ----------------\n");

	if (uname(&name) == 0) {
		debug_log(0, "System: %s %s %s %s %s\n", name.sysname,
			  name.nodename, name.release, name.version,
			  name.machine);
	}

	debug_dump(ptr, info->si_addr);

	debug_log(0, "---------------------- END CUT HERE -----------------\n");

	exit(-1);
}

static void
register_signals()
{
	struct sigaction act;

	memset(&act, 0, sizeof(act));
	act.sa_handler = handle_sigc;
	sigaction(SIGINT, &act, NULL);

	act.sa_handler = NULL;
	act.sa_sigaction = handle_sigsegv;
	act.sa_flags = SA_SIGINFO;
	sigaction(SIGSEGV, &act, NULL);
}

static inline struct timeval *
to_timeval(struct timeval *tv, int timeleft)
{
	tv->tv_sec = timeleft / 1000;
	tv->tv_usec = (timeleft % 1000) * 1000;
	return tv;
}

void
mblty_init_program(struct support_debug_conf *debug,
		   struct mblty_event_ops *ops)
{
	debug_conf = debug;
	mblty_global_events = ops;

	debug_init_facilities();
	support_clear_sockets();
	support_timers_init();

	register_signals();

	os_internal_init();
}

int
mblty_main_loop()
{
	int res, maxsock, timeleft;
	struct timeval tv, *ptv;
	fd_set rset, wset;

	while (1) {
		/* construct fd-sets */
		FD_ZERO(&rset);
		FD_ZERO(&wset);

		maxsock = 0;
		support_construct_fdset(&maxsock, &rset, &wset);

		timeleft = support_time_left();
		if (timeleft < 0)
			ptv = NULL;
		else
			ptv = to_timeval(&tv, timeleft);

		res = select(maxsock + 1, &rset, &wset, NULL, ptv);
		if (res < 0) {
			if (errno == EINTR)
				continue;
			break;
		}

		if (res > 0)
			support_call_sockets(&rset, &wset);

		support_handle_timers();
	}

	return 0;
}

void
mblty_copyright_header()
{
	debug_log(0, "MOBSIX -- Mobility Support for IPv6.\n");
	debug_log(0, "\n");
}

void
perform_shutdown(const char *message, ...)
{
	char buf[256];
	va_list vl;

	va_start(vl, message);
	vsnprintf(buf, sizeof(buf), message, vl);
	va_end(vl);

	debug_log(0, "\n");
	debug_log(0, " >>>\n");
	debug_log(0, " >>> %s.\n", buf);

	debug_log(0, " >>>\n");
	debug_log(0, "\n");

	mblty_shutdown();
}

int
mblty_sk_send(supsocket_t *sock, struct in6_addr *dst, void *buf, int length,
	      supsocket_txopt_t *txopt)
{
	return sock->ops->send(sock, dst, buf, length, txopt);
}

int
mblty_sk_recv(supsocket_t *sock, void *buf, int len, supsocket_rxparm_t *rxp)
{
	return sock->ops->recv(sock, buf, len, rxp);
}

int
mblty_sk_enable(supsocket_t *sock, supsocket_cap_t cap)
{
	return sock->ops->enable(sock, cap);
}

int
mblty_sk_disable(supsocket_t *sock, supsocket_cap_t cap)
{
	return sock->ops->disable(sock, cap);
}

int
mblty_sk_join_mc(supsocket_t *sock, struct mblty_os_intf *intf,
		 struct in6_addr *addr)
{
	return sock->ops->join_mc(sock, intf, addr);
}

int
mblty_sk_leave_mc(supsocket_t *sock, struct mblty_os_intf *intf,
		  struct in6_addr *addr)
{
	return sock->ops->leave_mc(sock, intf, addr);
}

int
mblty_sk_join_anycast(supsocket_t *sock, struct mblty_os_intf *intf,
		      struct in6_addr *addr)
{
	return sock->ops->join_anycast(sock, intf, addr);
}

int
mblty_sk_leave_anycast(supsocket_t *sock, struct mblty_os_intf *intf,
		       struct in6_addr *addr)
{
	return sock->ops->leave_anycast(sock, intf, addr);
}

