#ifdef DESOCK_BIND
#include <sys/socket.h>

#define _GNU_SOURCE
#include <unistd.h>

#include "syscall.h"
#include "desock.h"

/* Desocket bind if fd from socket() is valid, and fd meets DESOCK_FD domain. IP v4 for now.
 * Added check to ensure that we only desock 1 netwokr port number for now. This port number
 * is user defineable via environment variable. This was done for situation where you are trying
 * to fuzz a network server that might be listening on several port numbers and de-socketing them
 * all caused issues. 
 * TODO: add user defined option to disable selective bind desocketing based on port number.
 * TODO: add option for user to desocket multiple port numbers, protocols, and domain types.
 */
visible int 
bind (int fd, const struct sockaddr* addr, socklen_t len) {
    struct sockaddr_in *ss = (struct sockaddr_in *)addr;
    DEBUG_LOG("[%d] desock::bind(%d, %p, %d) = 0. Port=%hu.\n", gettid(), fd, addr, len, ntohs(ss->sin_port));

    if (VALID_FD (fd) && DESOCK_FD (fd) && (ntohs(ss->sin_port) == desock_port) && DESOCK_FD_V4(fd)) {
        // TODO: Create better lookup function for meeting desock criteria.

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
