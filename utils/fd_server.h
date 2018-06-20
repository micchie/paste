#ifndef FD_LIB_H
#define FD_LIB_H

#include <errno.h>
#include <net/if.h>
#include <stdint.h>
#include <sys/socket.h>

#include <net/netmap.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

struct fd_request {
#define FD_GET 1
#define FD_RELEASE 2
#define FD_CLOSE 3
#define FD_STOP 4
	uint8_t action;
	char if_name[NETMAP_REQ_IFNAMSIZ];
};

struct fd_response {
	int32_t result;
	struct nmreq req;
};

int send_fd(int socket, int fd, void *buf, size_t buf_size);

int recv_fd(int socket, int *fd, void *buf, size_t buf_size);

#endif /* FD_LIB_H */