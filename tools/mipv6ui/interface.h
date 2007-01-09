#ifndef MIPV6UI_INTERFACE_H
#define MIPV6UI_INTERFACE_H

#include <net/if.h>
#include "wireless.h"
#include <mblty/list-support.h>

struct interface_settings {
	struct list_entry entry;
	char ifname[IFNAMSIZ];
	int is_wireless;
	char essid[IW_ESSID_MAX_SIZE + 1];
};

void
interface_settings_add(const struct interface_settings *is);

/* returns NULL if not found */
struct interface_settings *
interface_settings_find(const char *ifname);

void
interface_settings_remove(struct interface_settings *is);


#endif

