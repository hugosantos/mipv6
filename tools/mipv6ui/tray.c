#include "tray.h"
#include <gtk/gtk.h>
#include <stdlib.h>
#include "eggtrayicon.h"

static GtkTooltips *tray_tips;
static GtkWidget *box;
static GtkWidget *tray;
static GtkWidget *tray_icon;
static GdkPixbuf *pixbuf_connected;
static GdkPixbuf *pixbuf_disconnected;

static gboolean tray_icon_clicked(GtkWidget *widget,
                           GdkEventButton *event,
                           gpointer data) {

	if (event->type == GDK_BUTTON_PRESS) {
	}

	return TRUE;
}

static gboolean tray_icon_pressed(GtkWidget *widget,
                           GdkEventButton *event,
                           gpointer data) {
	return TRUE;
}

static void tray_object_destroyed (gpointer data) {
}

static gint tray_icon_expose (GtkWidget* widget, GdkEventExpose *event) {
	return FALSE;
}

void tray_init() {
	tray = GTK_WIDGET(egg_tray_icon_new("MIPv6 Tray Icon"));
	box = gtk_event_box_new();
	g_signal_connect (G_OBJECT(box), "button_press_event",
			 	G_CALLBACK(tray_icon_clicked), NULL);
	g_signal_connect (G_OBJECT (box), "key_press_event",
			 	G_CALLBACK (tray_icon_pressed), NULL);
	g_object_set_data_full (G_OBJECT (tray), "tray-action-data", NULL,
				(GDestroyNotify) tray_object_destroyed);
	gtk_container_add (GTK_CONTAINER (tray), box);
	
	pixbuf_connected = gdk_pixbuf_scale_simple(
							gdk_pixbuf_new_from_file("icon.svg", NULL),
							24, 24, GDK_INTERP_BILINEAR);
	pixbuf_disconnected = gdk_pixbuf_scale_simple(
							gdk_pixbuf_new_from_file("icon2.svg", NULL),
							24, 24, GDK_INTERP_BILINEAR);

	tray_icon = gtk_image_new_from_pixbuf(pixbuf_disconnected);
	g_signal_connect (G_OBJECT (tray_icon), "expose_event",
			 	G_CALLBACK (tray_icon_expose), NULL);
	GTK_WIDGET_SET_FLAGS (box, GTK_CAN_FOCUS);
	gtk_container_add (GTK_CONTAINER (box), tray_icon);
	tray_tips = gtk_tooltips_new ();
	gtk_tooltips_set_tip (GTK_TOOLTIPS(tray_tips), box, "",
						  NULL);
	gtk_widget_show_all (tray);
}

void tray_set_tooltip(const char *msg) {
	gtk_tooltips_set_tip (GTK_TOOLTIPS(tray_tips), box, msg, NULL);
}

void tray_set_icon(int n) {
	switch (n) {
	case 0: /* connected */
		gtk_image_set_from_pixbuf(GTK_IMAGE(tray_icon), pixbuf_connected);
		break;

	case -1: /* disconnected */
		gtk_image_set_from_pixbuf(GTK_IMAGE(tray_icon), pixbuf_disconnected);
		break;

	default:
		printf("*** invalid icon\n");
		abort();
	}
}

