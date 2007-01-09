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
#include <ctype.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <mblty/base-support.h>

#include <mipv6/mipv6.h>

#define MAX_WORD_LENGTH		64
#define MAX_PARAMS		(MIPV6_CONF_MAX_PARAMS + 1)

static int
is_int(const char *in)
{
	char *end;

	strtol(in, &end, 10);

	return (*end) == 0;
}

static int
is_boolean(const char *in)
{
	return strcmp(in, "true") == 0 || strcmp(in, "false") == 0;
}

static int
is_onoff(const char *in)
{
	return strcmp(in, "on") == 0 || strcmp(in, "off") == 0;
}

static int
is_identifier(const char *in)
{
	if (!isalpha(in[0]))
		return 0;

	for (; *in; in++) {
		if (!isalnum(*in) && (*in) != '-' && (*in) != '_')
			return 0;
	}

	return 1;
}

static int
is_address(const char *in)
{
	struct in6_addr tmp;

	return inet_pton(AF_INET6, in, &tmp) > 0;
}

static int
is_prefix(const char *in)
{
	char buf[INET6_PREFIXSTRLEN], *sep;

	if (strlen(in) >= INET6_PREFIXSTRLEN)
		return 0;

	strcpy(buf, in);
	sep = strchr(buf, '/');
	if (sep) {
		(*sep) = 0;
		if (!is_int(sep + 1))
			return 0;
	}

	return is_address(buf);
}

static int
eat_realm_label(const char **inptr)
{
	const char *in = (*inptr);
	int count = 0;

	for (; *in && (isalnum(*in) ||
		      (in[1] && isalnum(in[1]) && (*in) == '-')); in++)
		count++;

	return count;
}

static int
is_domain(const char *in, int strict)
{
	if (!strict && is_address(in))
		return 1;

	while (*in) {
		int c = eat_realm_label(&in);
		if (c == 0)
			return 0;
		if (*in == 0)
			break;
		else if (*in != '.')
			return 0;
	}

	return 1;
}

static inline int
is_nai_username_char(char C)
{
	return isalnum(C) || C == '!' || C == '#' || C == '$' || C == '%' ||
			     C == '&' || C == '\''|| C == '*' || C == '+' ||
			     C == '-' || C == '/' || C == '=' || C == '?' ||
			     C == '^' || C == '_' || C == '`' || C == '{' ||
			     C == '|' || C == '}';
}

static int
is_nai_username(const char *in)
{
	for (; is_nai_username_char(*in); in++);

	return (*in) == 0;
}

static int
is_nai(const char *in)
{
	char *buf, *at;
	int res = 1;

	/* strdup here... */
	buf = strdup(in);
	at = strchr(buf, '@');

	if (at) {
		(*at) = 0;
		res = is_domain(at + 1, 1);
	}

	if (res)
		res = is_nai_username(buf);

	free(buf);

	return res;
}

static void
exit_with_error_fv(int line, const char *fmt, va_list vl)
{
	char buf[256];

	vsnprintf(buf, sizeof(buf), fmt, vl);

	debug_log(0, "\n");
	debug_log(0, " >>>\n");
	if (line) {
		debug_log(0, " >>> %s around line %i.\n", buf, line);
	} else {
		debug_log(0, " >>> %s.\n", buf);
	}
	debug_log(0, " >>>\n");
	debug_log(0, "\n");

	va_end(vl);

	mblty_shutdown();
}

static void
exit_with_error_f(int line, const char *fmt, ...)
{
	va_list vl;
	va_start(vl, fmt);
	exit_with_error_fv(line, fmt, vl);
}

static void
check_argument(int res, const char *type, const char *name, int arg, int line)
{
	char place[32];

	if (res)
		return;

	if (arg == 0)
		strcpy(place, "1st");
	else if (arg == 1)
		strcpy(place, "2nd");
	else if (arg == 2)
		strcpy(place, "3rd");
	else
		snprintf(place, sizeof(place), "%ith", arg);

	exit_with_error_f(line, "Expected %s as %s argument for '%s'",
		          type, place, name);
}

static void
check_arguments(int line, char *args[], int count, mipv6_conf_item_t *item)
{
	int i;

	for (i = 0; i < count; i++) {
		switch (item->params[i]) {
		case MIPV6_PARAM_T_INT:
			check_argument(is_int(args[i + 1]), "integer", args[0],
				       i, line);
			break;
		case MIPV6_PARAM_T_BOOLEAN:
			check_argument(is_boolean(args[i + 1]), "boolean",
				       args[0], i, line);
			break;
		case MIPV6_PARAM_T_ONOFF:
			check_argument(is_onoff(args[i + 1]), "on/off",
				       args[0], i, line);
			break;
		case MIPV6_PARAM_T_IDENTIFIER:
			check_argument(is_identifier(args[i + 1]), "identifier",
				       args[0], i, line);
			break;
		case MIPV6_PARAM_T_ADDRESS:
			check_argument(is_address(args[i + 1]), "address",
				       args[0], i, line);
			break;
		case MIPV6_PARAM_T_PREFIX:
			check_argument(is_prefix(args[i + 1]), "prefix",
				       args[0], i, line);
			break;
		case MIPV6_PARAM_T_DOMAIN:
			check_argument(is_domain(args[i + 1], 0), "domain name"
				       " or address", args[0], i, line);
			break;
		case MIPV6_PARAM_T_NAI:
			check_argument(is_nai(args[i + 1]), "NAI", args[0], i,
				       line);
			break;
		default:
			break;
		}
	}
}

static void
execute_expression(int line, int check, char *args[], int argcount,
		   mipv6_conf_item_t *items)
{
	mipv6_conf_item_t *item = NULL;
	int i, count;

	item = items;
	while (1) {
		if (item->name == NULL) {
			item = NULL;
			break;
		}

		if (strcmp(item->name, args[0]) == 0)
			break;

		item++;
	}

	if (check) {
		if (item == NULL)
			exit_with_error_f(line, "Unknown configuration item "
					  "'%s'", args[0]);

		count = 0;
		for (i = 0; i < MIPV6_CONF_MAX_PARAMS; i++) {
			if (item->params[i] != MIPV6_PARAM_T_NONE)
				count++;
			else
				break;
		}

		if (count != (argcount - 1))
			exit_with_error_f(line, "Argument count mismatch "
					  "for '%s', expected %i", args[0],
					  count);

		check_arguments(line, args, count, item);
	} else {
		item->handler(item, args, argcount);
	}
}

static void
parse_configuration_in(int check, FILE *fp, mipv6_conf_item_t *items)
{
	int wptr = 0, c, line = 1, col = 1, currarg = 0, comment = 0, a0ln, i;
	char wbuf[MAX_WORD_LENGTH], *params[MAX_PARAMS];

	while (1) {
		c = fgetc(fp);
		if (c < 0)
			break;

		if (check && !(isprint (c) || c == '\n'))
			exit_with_error_f(line, "Invalid character in column %i.",
					  col);
		col++;

		if (comment) {
			if (c == '\n') {
				comment = 0;
				line++;
			}
			continue;
		}

		if (isspace(c) || c == ';') {
			if (wptr > 0) {
				wbuf[wptr] = 0;
				wptr = 0;
				debug_assert(currarg < MAX_PARAMS,
					     "Too many parameters.");
				if (currarg == 0)
					a0ln = line;
				params[currarg++] = strdup(wbuf);
			}

			if (c == '\n') {
				line++;
				col = 1;
			}

			if (c == ';') {
				debug_assert(currarg > 0, "Empty expression.");
				execute_expression(a0ln, check, params,
						   currarg, items);
				for (i = 0; i < currarg; i++)
					free(params[i]);
				currarg = 0;
			}
		} else if (c == '#') {
			comment = 1;
		} else {
			wbuf[wptr++] = c;
		}

	}

	if (check && currarg > 0)
		exit_with_error_f(a0ln, "Unfinished expression");
}

void
parse_configuration(const char *filename, mipv6_conf_item_t *items)
{
	FILE *fp = fopen(filename, "r");

	if (fp == NULL)
		perform_shutdown("Failed to open configuration file");

	parse_configuration_in(1, fp, items);

	fseek(fp, 0, SEEK_SET);

	parse_configuration_in(0, fp, items);

	fclose(fp);
}

void
mipv6_parse_options(int argc, char *argv[], mipv6_conf_t *conf)
{
	int i;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-l") == 0) {
			i++;
			debug_assert(i < argc, "missing argument for -l");
			conf->debug.log_level = atoi(argv[i]);
		} else if (strcmp(argv[i], "-f") == 0) {
			i++;
			debug_assert(i < argc, "missing argument for -f");
			conf->debug.log_file = argv[i];
		} else if (strcmp(argv[i], "-c") == 0) {
			i++;
			debug_assert(i < argc, "missing argument for -c");
			conf->conf_file = argv[i];
		} else {
			/* unrecognized option */
		}
	}
}

void
mipv6_init_program(mipv6_conf_t *conf, struct mblty_event_ops *ops)
{
	mblty_init_program(&conf->debug, ops);
}

