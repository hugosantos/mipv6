#include "interface.h"
#include <string.h>
#include <stdlib.h>

static LIST_DEF(settings_list);

void
interface_settings_add(const struct interface_settings *is)
{
	struct interface_settings *new = (struct interface_settings *)
		malloc(sizeof(struct interface_settings));

	if (!new)
		return;

	list_add(&new->entry, &settings_list);

	strncpy(new->ifname, is->ifname, IFNAMSIZ);
	new->is_wireless = is->is_wireless;
	strncpy(new->essid, is->essid, IW_ESSID_MAX_SIZE + 1);
}

struct interface_settings *
interface_settings_find(const char *ifname)
{
	struct interface_settings *entry;
	
	list_for_each_entry(entry, &settings_list, entry) {
		if (strcmp(entry->ifname, ifname) == 0)
			return entry;
	}
	
	return NULL;
}

void
interface_settings_remove(struct interface_settings *is)
{
	list_del(&is->entry);
	free(is);
}

