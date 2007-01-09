#ifndef MIPV6UI_TRAY_H
#define MIPV6UI_TRAY_H

void tray_init();
void tray_set_tooltip(const char *msg);

/*  0: connected
 * -1: disconnected
 */
void tray_set_icon(int icon);

#endif

