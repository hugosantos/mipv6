/* vim:set ts=8 sw=8 tw=80: */

#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/select.h>

#include "mipv6/mn-helper.h"

void error(const char *msg) {
	fprintf(stderr, "error: %s: %s\n", msg, strerror(errno));
	exit(1);
}

int main() {
	int listen_fd, fd;
	struct sockaddr_un sun;
	const char sockpath[] = "/var/run/mipv6-mn-helper";
	struct mipv6_mn_helper_cmd cmd;

	if ((listen_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		error("socket");
	}

	if (unlink(sockpath) != 0)
		fprintf(stderr, "unlink: %s\n", strerror(errno));

	sun.sun_family = AF_UNIX;
	strcpy(sun.sun_path, sockpath);

	if (bind(listen_fd, (struct sockaddr *) &sun, sizeof(sun)) != 0) {
		error("bind");
	}

	if (listen(listen_fd, 0) != 0) {
		error("listen");
	}

	for (;;) {
		printf("waiting...\n");

		if ((fd = accept(listen_fd, NULL, NULL)) < 0) {
			error("accept");
		}

		printf("got connection\n");

		fd_set set;
		int n;

		for (;;) {
			FD_ZERO(&set);
			FD_SET(fd, &set);
			FD_SET(fileno(stdin), &set);

			n = select(fd + 1, &set, NULL, NULL, NULL);

			if (n < 0)
				error("select");

			if (FD_ISSET(fd, &set)) {
				n = recv(fd, &cmd, sizeof(cmd), 0);

				if (n < 0) {
					printf("recv error: %s\n",
					       strerror(errno));
					break;
				} else if (n == 0) {
					printf("peer shutdown\n");
					break;
				}

				printf("receive: %d %d %d\n", cmd.command,
				       cmd.type, cmd.u.value);
			}

			if (FD_ISSET(fileno(stdin), &set)) {
				scanf("%d %d %d", &cmd.command, &cmd.type,
				      &cmd.u.value);
				if (send(fd, &cmd,
					 sizeof(cmd), 0) != sizeof(cmd))
					error("send() != sizeof(cmd)");
			}
		}

		close(fd);
	}

	return 0;
}

