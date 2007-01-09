#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "wireless.h"

int iface_is_wireless(const char *iface) {
	struct iwreq req;
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	int ret;
	
	memset(&req, 0, sizeof(req));
	strcpy(req.ifr_name, iface);

	ret = ! (ioctl(sock, SIOCGIWNAME, &req) < 0);
	close(sock);
	return ret;
}

int iface_wireless_set_essid(const char *iface, const char *essid) {
	struct iwreq req;
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	char essidbuffer[IW_ESSID_MAX_SIZE + 1];
	int n;

	memset(&req, 0, sizeof(req));
	strcpy(req.ifr_name, iface);
	req.u.mode = IW_MODE_INFRA;

	if ((n = ioctl(sock, SIOCSIWMODE, &req)) < 0) {
		close(sock);
		return n;
	}

	memset(&req, 0, sizeof(req));
	strcpy(req.ifr_name, iface);
	req.u.essid.flags = 1;
	strcpy(essidbuffer, essid);
	req.u.essid.pointer = essidbuffer;
	req.u.essid.length = strlen(essidbuffer) + 1;

	if ((n = ioctl(sock, SIOCSIWESSID, &req)) < 0) {
		close(sock);
		return n;
	}

	close(sock);

	return 0;
}

