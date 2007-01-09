#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct ip6_bcache_update {
	int dir;
	struct in6_addr local;
	struct in6_addr remote;
	struct in6_addr coa;
};

#define IPV6_BCACHE_UPDATE 85

int main(int argc, char *argv[])
{
	struct ip6_bcache_update u;
	int sock;

	if (argc < 5) {
		printf("arguments?\n");
		return -1;
	}

	sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	if (sock < 0) {
		perror("socket()");
		return -1;
	}

	u.dir = atoi(argv[1]);
	inet_pton(AF_INET6, argv[2], &u.local);
	inet_pton(AF_INET6, argv[3], &u.remote);
	inet_pton(AF_INET6, argv[4], &u.coa);

	if (setsockopt(sock, IPPROTO_IPV6, IPV6_BCACHE_UPDATE, &u, sizeof(u)) < 0) {
		perror("setsockopt(IPV6_BCACHE_UPDATE)");
		return -1;
	}

	printf("ok.\n");

	return 0;
}

