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
 * TODO: add option for user to desocket multiple port numbers, protocols, and domain types.
 * TODO: Make these caller defined details permanent for such calls as fill_local_sockaddr.
 */
visible int 
bind (int fd, const struct sockaddr* addr, socklen_t len) {
    struct sockaddr_in *ss = (struct sockaddr_in *)addr;
    uint16_t port = ntohs(ss->sin_port);
    char ip_str[MAX_IPV4_LEN + 1];
    get_ip_str(addr, ip_str, MAX_IPV4_LEN + 1);
    int result = 0;
    DEBUG_LOG("[%s:%d:%d] (%d, %p, %d) Address: %s, Port: %hu.\n", __FUNCTION__, __LINE__, gettid(), fd, addr, len, ip_str, port);

    if (VALID_FD (fd) && DESOCK_FD (fd) && (port == desock_port_local) && DESOCK_FD_V4(fd)) {
        // TODO: Create better lookup function for meeting desock criteria.

        fd_table[fd].desock = 1;
        fd_table[fd].port = port;

        //Need to store to help when desocketing services that depend on it.
        fd_table[fd].address = (((struct sockaddr_in *)addr)->sin_addr.s_addr); 

        result = 0;
        DEBUG_LOG("[%s:%d:%d] Desocketed.\n", __FUNCTION__, __LINE__, gettid());
    } else {
        result = socketcall (bind, fd, addr, len, 0, 0, 0);
    }

    DEBUG_LOG("[%s:%d:%d] result: %d.\n", __FUNCTION__, __LINE__, gettid(), result);
    return result;
}

/* Desocket bind if fd from socket() is valid, and fd meets DESOCK_FD domain. IP v4 for now.
 * Added check to ensure that we only desock 1 netwokr port number for now. This port number
 * is user defineable via environment variable. This was done for situation where you are trying
 * to fuzz a network server that might be listening on several port numbers and de-socketing them
 * all caused issues.
 * TODO: add option for user to desocket multiple port numbers, protocols, and domain types.
 * TODO: Make these caller defined details permanent for such calls as fill_local_sockaddr.
 */
visible int 
__bind (int fd, const struct sockaddr* addr, socklen_t len) {
    struct sockaddr_in *ss = (struct sockaddr_in *)addr;
    DEBUG_LOG("[%d] desock::bind(%d, %p, %d) = 0. Port=%hu.\n", gettid(), fd, addr, len, ntohs(ss->sin_port));

    if (VALID_FD (fd) && DESOCK_FD (fd) && (ntohs(ss->sin_port) == desock_port_local) && DESOCK_FD_V4(fd)) {
        // TODO: Create better lookup function for meeting desock criteria.

        fd_table[fd].desock = 1;
        fd_table[fd].port = ntohs(ss->sin_port);

        //Need to store to help when desocketing services that depend on it.
        fd_table[fd].address = (((struct sockaddr_in *)addr)->sin_addr.s_addr); 

        char ip_str[MAX_IPV4_LEN + 1];
        DEBUG_LOG("[%d] desock::bind(%d, %p, %d) = 0. ip: %s, Port=%hu. Success\n", gettid(), fd, addr, len, get_ip_str(addr, ip_str, MAX_IPV4_LEN+1), ntohs(ss->sin_port));

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
