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
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h> /* for abort() */
#include <sys/time.h>

#if defined(__GLIBC__) && !defined(__UCLIBC__)
#include <execinfo.h>
#include <sys/ucontext.h>
#endif

#include <mblty/base-support.h>

static FILE *extra_out = NULL;

void
debug_init_facilities()
{
	if (debug_conf->log_file)
		extra_out = fopen(debug_conf->log_file, "w");

	mblty_copyright_header();

	if (debug_conf->log_file && extra_out == NULL) {
		debug_log(0, " ??\n");
		debug_log(0, " ?? Failed to open %s for log output.\n",
			  debug_conf->log_file);
		debug_log(0, " ??\n");
	}
}

void
debug_close_facilities()
{
	if (extra_out) {
		fclose(extra_out);
		extra_out = NULL;
	}
}

void
debug_assert_ext(const char *function, const char *file, int line,
		 const char *message, ...)
{
	char buf[256];
	va_list vl;

	va_start(vl, message);
	vsnprintf(buf, sizeof(buf), message, vl);
	va_end(vl);

	debug_logf(0, "%s (%s in %s:%i)\n", buf, function, file, line);
	abort();
}

static void
debug_logf_generic(FILE *outf, int level, const char *format, va_list vl)
{
	struct timeval tv;
	char dfmt[64];

	gettimeofday(&tv, NULL);
	strftime(dfmt, sizeof(dfmt), "%H:%M:%S", localtime(&tv.tv_sec));
	fprintf(outf, "%s.%06u [%i] ", dfmt, (uint32_t)tv.tv_usec, level);
	vfprintf(outf, format, vl);
}

static void
debug_logfv(int level, const char *format, va_list vl)
{
	va_list vltmp;
	va_copy(vltmp, vl);

	debug_logf_generic(stderr, level, format, vl);
	if (extra_out) {
		debug_logf_generic(extra_out, level, format, vltmp);
		fflush(extra_out);
	}

	va_end(vltmp);
}

void
debug_logf(int level, const char *format, ...)
{
	va_list vl;
	va_start(vl, format);
	debug_logfv(level, format, vl);
	va_end(vl);
}

#define MAX_BACKTRACE_LEVELS	32

static void
dump_backtrace(int level)
{
#if defined(__GLIBC__) && !defined(__UCLIBC__)
	void *bt[MAX_BACKTRACE_LEVELS];
	char **btnames;
	int i, count;

	count = backtrace(bt, MAX_BACKTRACE_LEVELS);
	btnames = backtrace_symbols(bt, count);

	debug_log(level, "Current backtrace:\n");
	for (i = 0; i < count; i++) {
		debug_log(level, "  #%i %s\n", i + 1, btnames[i]);
	}

	free(btnames);
#else
	debug_log(level, "Backtrace not supported in this platform.\n");
#endif
}

void
debug_dump(void *ptr, void *at)
{
#if defined(__GLIBC__) && !defined(__UCLIBC__)
	void *bt[MAX_BACKTRACE_LEVELS], *PC = NULL;
	ucontext_t *uc = ptr;
	char **btnames;

#if defined(__i386__)
	PC = (void *)uc->uc_mcontext.gregs[REG_EIP];
#endif

	if (PC) {
		bt[0] = PC;
		btnames = backtrace_symbols(bt, 1);
		debug_log(0, "Failed to access %p in %s.\n", at, btnames[0]);
		free(btnames);
	} else {
		debug_log(0, "Failed to access %p in unknown location.\n");
	}
#endif

	dump_backtrace(0);
}

void
debug_callerf(int level, const char *format, ...)
{
	va_list vl;

	va_start(vl, format);
	debug_logfv(level, format, vl);
	va_end(vl);

	dump_backtrace(level);
}

