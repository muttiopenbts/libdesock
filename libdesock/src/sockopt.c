#define _GNU_SOURCE
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>

#include "desock.h"
#include "syscall.h"

visible int setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen)
{
    DEBUG_LOG("[%s:%d:%d] (%d, %d, %d, %p, %lu)\n", __FUNCTION__, __LINE__, gettid(), fd, level, optname, optval, optlen);
    int result = 0;

    if (VALID_FD(fd) && fd_table[fd].desock)
    {
        DEBUG_LOG("[%s:%d:%d] result: %d. Desock\n", __FUNCTION__, __LINE__, gettid(), result);
        result = 0;
    }
    else
    {
        result = __socketcall(setsockopt, fd, level, optname, optval, optlen, 0);
        result = __syscall_ret(result);
        DEBUG_LOG("[%s:%d:%d] result: %d. Desock\n", __FUNCTION__, __LINE__, gettid(), result);
    }

    return result;
}
