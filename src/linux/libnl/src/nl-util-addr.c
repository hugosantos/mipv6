/*
 * src/nl-util-addr.c     Address Helper
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Copyright (c) 2003-2005 Thomas Graf <tgraf@suug.ch>
 */

#include "utils.h"

int main(int argc, char *argv[])
{
	int err;
	char host[256];
	struct nl_addr *a;

	if (argc < 2) {
		fprintf(stderr, "Usage: nl-util-addr <address>\n");
		return -1;
	}
	
	a = nl_addr_parse(argv[1], AF_UNSPEC);
	if (a == NULL) {
		fprintf(stderr, "Cannot parse address \"%s\"\n", argv[1]);
		return -1;
	}

	err = nl_addr_resolve(a, host, sizeof(host));
	if (err != 0) {
		fprintf(stderr, "Cannot resolve address \"%s\": %d\n",
			argv[1], err);
		return -1;
	}

	printf("%s\n", host);

	return 0;
}
