#define _GNU_SOURCE
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>

#include "desock.h"
#include "syscall.h"

/* Tested a tcp v4 server and works.
 * TODO: Test desocketing a client calling this function.
 */
visible int getsockname(int fd, struct sockaddr *restrict addr, socklen_t *restrict len)
{
    if (VALID_FD(fd) && fd_table[fd].desock)
    {
        DEBUG_LOG("[%d] desock::getsockname(%d, %p, %p) Desock\n", gettid(), fd, addr, len);

        // If we are desocketing a server, then assume we are the server and make sure caller gets
        // sockaddr related to local env variables.
        if (fd_table[fd].listening)
        {
            DEBUG_LOG("[%d] desock::getsockname listening.\n", gettid());
            fill_remote_sockaddr(fd, addr, len);
        }
        else
        {
            // Assuming the fd is associated with an accept()
            DEBUG_LOG("[%d] desock::getsockname remote.\n", gettid());
            fill_local_sockaddr(fd, addr, len);
            // We have to do this trick because we are assuming a tcp connection has occured and
            // caller wants to know which local ip the remote host has connected to.
            struct sockaddr_in *ptr = (struct sockaddr_in *)addr;
            inet_aton(desock_localipv4, &ptr->sin_addr);
        }

        char ip_str[MAX_IPV4_LEN + 1];
        get_ip_str(addr, ip_str, MAX_IPV4_LEN + 1);
        DEBUG_LOG("[%d] %s result: %s.\n", gettid(), __FUNCTION__, ip_str);

        return 0;
    }
    else
    {
        DEBUG_LOG("[%d] desock::getsockname(%d, %p, %p) = 0. No desock\n", gettid(), fd, addr, len);
        return socketcall(getsockname, fd, addr, len, 0, 0, 0);
    }
}
