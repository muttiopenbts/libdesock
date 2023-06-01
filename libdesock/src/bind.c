#ifdef DESOCK_BIND
#include <sys/socket.h>

#define _GNU_SOURCE
#include <unistd.h>

#include "syscall.h"
#include "desock.h"

visible int bind (int fd, const struct sockaddr* addr, socklen_t len) {
    /* Desocket bind if fd from socket() is valid, and fd meets DESOCK_FD domain
        requirements.
     */
    struct sockaddr_in *ss = (struct sockaddr_in *)addr;
    DEBUG_LOG("[%d] desock::bind(%d, %p, %d) = 0. Port=%hu.\n", gettid(), fd, addr, len, ntohs(ss->sin_port));

    if (VALID_FD (fd) && DESOCK_FD (fd) && (ntohs(ss->sin_port) == 179)) {
        // Only desock TCP BGP
        // TODO: Create lookup function for meeting desock criteria.

        fd_table[fd].desock = 1;
        fd_table[fd].port = ntohs(ss->sin_port);
        DEBUG_LOG("[%d] desock::bind(%d, %p, %d) = 0. Port=%hu. Success\n", gettid(), fd, addr, len, ntohs(ss->sin_port));

        return 0;
    } else {
        return socketcall (bind, fd, addr, len, 0, 0, 0);
    }
}

#ifdef DEBUG
visible int _debug_real_bind (int fd, const struct sockaddr* addr, socklen_t len) {
    return socketcall (bind, fd, addr, len, 0, 0, 0);
}
#endif

#endif
