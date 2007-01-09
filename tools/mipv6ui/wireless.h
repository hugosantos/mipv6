#ifndef MIPV6UI_WIRELESS_H
#define MIPV6UI_WIRELESS_H

#define __user

#include "wireless.18.h"

int iface_is_wireless(const char *iface);

int iface_wireless_set_essid(const char *iface, const char *essid);

#endif

