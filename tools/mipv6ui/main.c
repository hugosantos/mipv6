#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <gtk/gtk.h>
#include <net/if.h>
#include <signal.h>
#include <errno.h>

#include <mipv6/mn-helper.h>
#include "wireless.h"
#include "interface.h"
#include "tray.h"

#define _(x) (x)

GtkWidget *window;
GtkWidget *vbox1;
GtkWidget *hbox2;
GtkWidget *icon;
GtkWidget *vbox2;
GtkWidget *hbox4;
GtkWidget *primary_label;
GtkWidget *hbox5;
GtkWidget *secondary_label;
GtkWidget *hbox6;
GtkWidget *label4;
GtkWidget *essid_entry;
GtkWidget *always_use_checkbox;
GtkWidget *hbuttonbox1;
GtkWidget *button_no;
GtkWidget *button_yes;
GtkWidget *button_close;

GIOChannel *channel;
struct interface_settings static_settings;
struct interface_settings *settings;
struct mipv6_mn_helper_cmd cmd;


static void daemon_disconnected();
static void daemon_connect();

static void send_reply() {
	send(g_io_channel_unix_get_fd(channel), &cmd, sizeof(cmd), 0);
}

static void use_interface() {
	if (settings->is_wireless) {
		iface_wireless_set_essid(settings->ifname, settings->essid);
	}

	send_reply();
}

static void button_callback(GtkWidget *widget, gpointer data) {
	int n = GPOINTER_TO_INT(data);

	if (n == 2) {
		/* user clicked "yes" */

		if (static_settings.is_wireless) {
			strncpy(static_settings.essid,
					gtk_entry_get_text(GTK_ENTRY(essid_entry)),
					IW_ESSID_MAX_SIZE + 1);
			static_settings.essid[IW_ESSID_MAX_SIZE] = '\0';
		} else {
			static_settings.essid[0] = '\0';
		}

		settings = &static_settings;
		use_interface();

		if (gtk_toggle_button_get_active(
			GTK_TOGGLE_BUTTON(always_use_checkbox))) {
			printf("saving settings for interface %s\n", settings->ifname);
			interface_settings_add(settings);
		}
	} else if (n == 0) {
		/* user clicked "close" (an error occured) */
		
		/*gtk_main_quit();*/
	}
	
	gtk_widget_hide(window);
}

static gboolean delete_callback(GtkWidget *widget, GdkEvent *event,
								gpointer data) {
	gtk_main_quit();
	return TRUE;
}

static GtkWidget *create_window (void) {
  window = gtk_window_new (GTK_WINDOW_TOPLEVEL);
  gtk_container_set_border_width (GTK_CONTAINER (window), 5);
  gtk_window_set_title (GTK_WINDOW (window), _("Mobility event"));
  gtk_window_set_resizable (GTK_WINDOW (window), FALSE);

  vbox1 = gtk_vbox_new (FALSE, 5);
  gtk_widget_show (vbox1);
  gtk_container_add (GTK_CONTAINER (window), vbox1);

  hbox2 = gtk_hbox_new (FALSE, 0);
  gtk_widget_show (hbox2);
  gtk_box_pack_start (GTK_BOX (vbox1), hbox2, TRUE, TRUE, 0);

  icon = gtk_image_new_from_stock ("gtk-dialog-info", GTK_ICON_SIZE_DIALOG);
  gtk_widget_show (icon);
  gtk_box_pack_start (GTK_BOX (hbox2), icon, FALSE, TRUE, 10);

  vbox2 = gtk_vbox_new (FALSE, 10);
  gtk_widget_show (vbox2);
  gtk_box_pack_start (GTK_BOX (hbox2), vbox2, TRUE, TRUE, 0);
  gtk_container_set_border_width (GTK_CONTAINER (vbox2), 5);

  hbox4 = gtk_hbox_new (FALSE, 0);
  gtk_widget_show (hbox4);
  gtk_box_pack_start (GTK_BOX (vbox2), hbox4, FALSE, FALSE, 0);

  primary_label = gtk_label_new (_("<b>A new interface is available.</b>"));
  gtk_widget_show (primary_label);
  gtk_box_pack_start (GTK_BOX (hbox4), primary_label, FALSE, FALSE, 0);
  gtk_label_set_use_markup (GTK_LABEL (primary_label), TRUE);

  hbox5 = gtk_hbox_new (FALSE, 0);
  gtk_widget_show (hbox5);
  gtk_box_pack_start (GTK_BOX (vbox2), hbox5, FALSE, FALSE, 0);

  secondary_label = gtk_label_new (_("Do you want to use the new interface <b>eth0</b> for mobility?"));
  gtk_widget_show (secondary_label);
  gtk_box_pack_start (GTK_BOX (hbox5), secondary_label, FALSE, FALSE, 0);
  gtk_label_set_use_markup (GTK_LABEL (secondary_label), TRUE);

  hbox6 = gtk_hbox_new (FALSE, 10);
  gtk_box_pack_start (GTK_BOX (vbox2), hbox6, FALSE, FALSE, 0);

  label4 = gtk_label_new (_("ESSID"));
  gtk_widget_show (label4);
  gtk_box_pack_start (GTK_BOX (hbox6), label4, FALSE, FALSE, 0);

  essid_entry = gtk_entry_new ();
  gtk_widget_show (essid_entry);
  gtk_box_pack_start (GTK_BOX (hbox6), essid_entry, FALSE, TRUE, 0);
  gtk_entry_set_max_length (GTK_ENTRY (essid_entry), 16);
  gtk_entry_set_width_chars (GTK_ENTRY (essid_entry), 16);

  always_use_checkbox = gtk_check_button_new_with_mnemonic (_("Always use this interface when available"));
  gtk_widget_show (always_use_checkbox);
  gtk_box_pack_start (GTK_BOX (vbox2), always_use_checkbox, FALSE, FALSE, 0);
  gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (always_use_checkbox), FALSE);

  hbuttonbox1 = gtk_hbutton_box_new ();
  gtk_widget_show (hbuttonbox1);
  gtk_box_pack_start (GTK_BOX (vbox1), hbuttonbox1, FALSE, TRUE, 0);
  gtk_button_box_set_layout (GTK_BUTTON_BOX (hbuttonbox1), GTK_BUTTONBOX_END);
  gtk_box_set_spacing (GTK_BOX (hbuttonbox1), 10);

  button_no = gtk_button_new_from_stock ("gtk-no");
  gtk_widget_show (button_no);
  gtk_container_add (GTK_CONTAINER (hbuttonbox1), button_no);
  GTK_WIDGET_SET_FLAGS (button_no, GTK_CAN_DEFAULT);

  button_yes = gtk_button_new_from_stock ("gtk-yes");
  gtk_widget_show (button_yes);
  gtk_container_add (GTK_CONTAINER (hbuttonbox1), button_yes);
  GTK_WIDGET_SET_FLAGS (button_yes, GTK_CAN_DEFAULT);

  button_close = gtk_button_new_from_stock ("gtk-close");
  gtk_container_add (GTK_CONTAINER (hbuttonbox1), button_close);
  GTK_WIDGET_SET_FLAGS (button_close, GTK_CAN_DEFAULT);

  return window;
}

static void set_primary_label(const char *str) {
	gtk_label_set_markup(GTK_LABEL(primary_label), str);	
}

static void set_secondary_label(const char *str) {
	gtk_label_set_markup(GTK_LABEL(secondary_label), str);	
}

static void set_secondary_label_enabled(gboolean enabled) {
	if (enabled) {
		gtk_widget_show(secondary_label);
	} else {
		gtk_widget_hide(secondary_label);
	}
}

static void set_essid_entry_enabled(gboolean enabled) {
	if (enabled) {
		gtk_widget_show(hbox6);
	} else {
		gtk_widget_hide(hbox6);
	}
}

static void set_icon_info() {
  gtk_image_set_from_stock(GTK_IMAGE(icon), "gtk-dialog-info",
						   GTK_ICON_SIZE_DIALOG);
}

static void set_icon_error() {
  gtk_image_set_from_stock(GTK_IMAGE(icon), "gtk-dialog-error",
						   GTK_ICON_SIZE_DIALOG);
}

static void set_buttons_yes_no_enabled(gboolean enabled) {
	if (enabled) {
		gtk_widget_show(button_yes);
		gtk_widget_show(button_no);
	} else {
		gtk_widget_hide(button_yes);
		gtk_widget_hide(button_no);
	}
}

static void set_button_close_enabled(gboolean enabled) {
	if (enabled) {
		gtk_widget_show(button_close);
	} else {
		gtk_widget_hide(button_close);
	}
}

static void set_always_use_checkbox_enabled(gboolean enabled) {
	if (enabled) {
		gtk_widget_show(always_use_checkbox);
	} else {
		gtk_widget_hide(always_use_checkbox);
	}
}

static void set_error_dialog(const char *error) {
	set_primary_label(error);
	set_secondary_label_enabled(FALSE);
	set_essid_entry_enabled(FALSE);
	set_icon_error();
	set_buttons_yes_no_enabled(FALSE);
	set_button_close_enabled(TRUE);
	set_always_use_checkbox_enabled(FALSE);
}

static void set_info_dialog(const char *msg1, const char *msg2,
							gboolean entryenable) {
	set_primary_label(msg1);
	set_secondary_label_enabled(TRUE);
	set_secondary_label(msg2);
	set_essid_entry_enabled(entryenable);
	set_icon_info();
	set_buttons_yes_no_enabled(TRUE);
	set_button_close_enabled(FALSE);
	set_always_use_checkbox_enabled(TRUE);
}

static gboolean sock_callback(GIOChannel *channel, GIOCondition condition, 
							  gpointer data) {
	int n;
	char buffer[IFNAMSIZ + 200];
	gboolean ret = TRUE;

	n = recv(g_io_channel_unix_get_fd(channel), &cmd, sizeof(cmd), 0);

	if (n < 0) {
		sprintf(buffer, "An error occured while communicating with the daemon\n"
				"recv: %s", strerror(errno));
		set_error_dialog(buffer);
		ret = FALSE;
		daemon_disconnected();
	} else if (n == 0) {
		/*
		sprintf(buffer, "Communication with the daemon has ended.");
		set_error_dialog(buffer);
		ret = FALSE;
		*/
		daemon_disconnected();
		return FALSE;
	} else if (cmd.command == MN_H_CMD_ADDINTF) {
		strcpy(static_settings.ifname, cmd.u.intfname);

		/* check if we have stored settings for this interface */
		settings = interface_settings_find(static_settings.ifname);

		if (settings != NULL) {
			/* use stored settings, skip dialog */
			printf("using saved settings for interface %s\n",
				   settings->ifname);
			use_interface();
			return TRUE;
		}

		sprintf(buffer, "Do you want to use the new interface <b>%s</b> "
				"for mobility?", static_settings.ifname);

		static_settings.is_wireless =
			iface_is_wireless(static_settings.ifname);

		if (static_settings.is_wireless) {
			set_info_dialog("<b>A new wireless interface is now "
							"available.</b>", buffer, 1);
		} else {
			set_info_dialog("<b>A new interface is now available.</b>",
							buffer, 0);
		}
	} else if (cmd.command == MN_H_CMD_RO) {
		send_reply();
		return TRUE;
	} else {
		sprintf(buffer, "Unknown command from daemon: %d", cmd.command);
		set_error_dialog(buffer);
		ret = FALSE;
	}

	gtk_widget_show(window);

	return ret;
}

static void daemon_disconnected() {
	g_io_channel_unref(channel);
	channel = NULL;
	tray_set_tooltip("MIPv6 is not running");
	tray_set_icon(-1);
	daemon_connect();
}

static void daemon_connect_failed() {
	/* retry in 1 second */
	alarm(1);
}

static void daemon_connect_success() {
	tray_set_tooltip("MIPv6 is running");
	tray_set_icon(0);
}

static void daemon_connect() {
	int fd;
	struct sockaddr_un sun;
	const char sockpath[] = "/var/run/mipv6-mn-helper";

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "error: socket: %s\n", strerror(errno));
		exit(1);
	}

	sun.sun_family = AF_UNIX;
	strcpy(sun.sun_path, sockpath);

	if (connect(fd, (struct sockaddr *) &sun, sizeof(sun)) != 0) {
		daemon_connect_failed();
		return;
		/*
		fprintf(stderr, "error: connect: %s\n", strerror(errno));
		exit(1);
		*/
	}

	channel = g_io_channel_unix_new(fd);
	g_io_add_watch(channel, G_IO_IN, sock_callback, NULL);
	
	daemon_connect_success();
}

static void connect_callbacks() {
	g_signal_connect(window, "delete_event", G_CALLBACK(delete_callback),
					 NULL);
	g_signal_connect(button_close, "clicked", G_CALLBACK(button_callback),
					 GINT_TO_POINTER(0));
	g_signal_connect(button_no, "clicked", G_CALLBACK(button_callback),
					 GINT_TO_POINTER(1));
	g_signal_connect(button_yes, "clicked", G_CALLBACK(button_callback),
					 GINT_TO_POINTER(2));
}

static void signal_alarm_handler(int sig) {
	daemon_connect();
}

static void install_signal_handlers() {
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = signal_alarm_handler;

	if (sigaction(SIGALRM, &sa, NULL) < 0) {
		printf("sigaction() failed: %s\n", strerror(errno));
		exit(1);
	}
}

int main(int argc, char *argv[]) {

	gtk_init(&argc, &argv);
	install_signal_handlers();

	window = create_window();
	connect_callbacks();
	tray_init();
	tray_set_tooltip("MIPv6 is not running");
	tray_set_icon(-1);

	gtk_widget_realize(window);

	daemon_connect();

	gtk_main();

	return 0;
}

