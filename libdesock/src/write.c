#define _GNU_SOURCE
#define __USE_GNU
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>

#include "syscall.h"
#include "desock.h"
#include "hooks.h"
#include "fsm.h"
#include <execinfo.h>
#include <stdio.h>
#include <pthread.h>

static long internal_writev(const struct iovec *iov, int len)
{
    DEBUG_LOG("[%s:%d:%d] Start len: %d\n", __FUNCTION__, __LINE__, gettid(), len);
    int written = 0;

    for (int i = 0; i < len; ++i)
    {
        int offset = 0, r;

        do
        {
            r = hook_output((char *)iov[i].iov_base + offset, iov[i].iov_len - offset);

            if (r == -1)
            {
                return -1;
            }

            written += r;
            offset += r;
        } while (offset < iov[i].iov_len && r > 0);
    }

    return written;
}

visible ssize_t write(int fd, const void *buf, size_t count)
{
    DEBUG_LOG("[%s:%d:%d] Start (%d, %p, %lu).\n", __FUNCTION__, __LINE__, gettid(), fd, buf, count);
    int result = 0;

    if (VALID_FD(fd) && fd_table[fd].desock)
    {
        DEBUG_LOG("[%s:%d:%d] Desocket\n", __FUNCTION__, __LINE__, gettid());
        result = hook_output(buf, count);
    }
    else
    {
        DEBUG_LOG("[%s:%d:%d]\n", __FUNCTION__, __LINE__, gettid());
        result = syscall_cp(SYS_write, fd, buf, count);
    }

    DEBUG_LOG("[%s:%d:%d] End result: %d.\n", __FUNCTION__, __LINE__, gettid(), result);
    return result;
}

visible ssize_t send(int fd, const void *buf, size_t len, int flags)
{
    if (VALID_FD(fd) && fd_table[fd].desock)
    {
        int r = hook_output(buf, len);
        DEBUG_LOG("[%d] desock::send(%d, %p, %lu, %d) = %d\n", gettid(), fd, buf, len, flags, r);
        return r;
    }
    else
    {
        return sendto(fd, buf, len, flags, 0, 0);
    }
}

visible ssize_t sendto(int fd, const void *buf, size_t len, int flags, const struct sockaddr *addr, socklen_t alen)
{
    if (VALID_FD(fd) && fd_table[fd].desock)
    {
        int r = hook_output(buf, len);
        DEBUG_LOG("[%d] desock::sendto(%d, %p, %lu, %d, %p, %lu) = %d\n", gettid(), fd, buf, len, flags, addr, alen, r);
        return r;
    }
    else
    {
        return socketcall_cp(sendto, fd, buf, len, flags, addr, alen);
    }
}

visible ssize_t sendmsg(int fd, const struct msghdr *msg, int flags)
{
    if (VALID_FD(fd) && fd_table[fd].desock)
    {
        int r = internal_writev(msg->msg_iov, msg->msg_iovlen);
        DEBUG_LOG("[%d] desock::sendmsg(%d, %p, %d) = %d\n", gettid(), fd, msg, flags, r);
        return r;
    }
    else
    {
        return socketcall_cp(sendmsg, fd, msg, flags, 0, 0, 0);
    }
}

visible int sendmmsg(int fd, struct mmsghdr *msgvec, unsigned int vlen, int flags)
{
    if (VALID_FD(fd) && fd_table[fd].desock)
    {
        DEBUG_LOG("[%d] desock::sendmmsg(%d, %p, %d, %d)", gettid(), fd, msgvec, vlen, flags);

        int i;

        for (i = 0; i < vlen; ++i)
        {
            msgvec[i].msg_len = internal_writev(msgvec[i].msg_hdr.msg_iov, msgvec[i].msg_hdr.msg_iovlen);

            if (msgvec[i].msg_len == -1)
            {
                DEBUG_LOG(" = -1\n");
                return -1;
            }
        }

        int r = (i == vlen || i == 0) ? i : (i + 1);
        DEBUG_LOG(" = %d\n", r);
        return r;
    }
    else
    {
        return syscall_cp(SYS_sendmmsg, fd, msgvec, vlen, flags);
    }
}

#define MAX_STACK_FRAMES 64
static void *stack_traces[MAX_STACK_FRAMES];
#define PROGRAM_NAME "rpd"

/* Taken from https://spin.atomicobject.com/2013/01/13/exceptions-stack-traces-c/
 */
void posix_print_stack_trace()
{
    int i, trace_size = 0;
    char **messages = (char **)NULL;

    trace_size = backtrace(stack_traces, MAX_STACK_FRAMES);
    messages = backtrace_symbols(stack_traces, trace_size);

    DEBUG_LOG("[%s:%d:%d]\n", __FUNCTION__, __LINE__, gettid());
    /* skip the first couple stack frames (as they are this function and
       our handler) and also skip the last frame as it's (always?) junk. */
    // for (i = 3; i < (trace_size - 1); ++i)
    // we'll use this for now so you can see what's going on
    for (i = 0; i < trace_size; ++i)
    {
        DEBUG_LOG("[%s:%d:%d] message: %s\n", __FUNCTION__, __LINE__, gettid(), messages[i]);
        // if (addr2line(PROGRAM_NAME, stack_traces[i]) != 0)
        //{
        //     printf("  error determining line # for: %s\n", messages[i]);
        // }
    }
    if (messages)
    {
        free(messages);
    }
}

/* Resolve symbol name and source location given the path to the executable
   and an address */
int addr2line(char const *const program_name, void const *const addr)
{
    char addr2line_cmd[512] = {0};

/* have addr2line map the address to the relent line in the code */
#ifdef __APPLE__
    /* apple does things differently... */
    sprintf(addr2line_cmd, "atos -o %.256s %p", program_name, addr);
#else
    sprintf(addr2line_cmd, "addr2line -f -p -e %.256s %p", program_name, addr);
#endif

    /* This will print a nicely formatted string specifying the
       function and source line of the address */
    return system(addr2line_cmd);
}

/* @param[1]    The file descriptor to write to.
 * @param[2]    An array of `iovec` structures.
 * @param[3]    The number of `iovec` structures in the array.
 */
visible ssize_t writev(int fd, const struct iovec *iov, int iovcnt)
{
    DEBUG_LOG("[%s:%d:%d] Start (%d, %p, %d)\n", __FUNCTION__, __LINE__, gettid(), fd, iov, iovcnt);
    int result = 0;

    if (VALID_FD(fd) && fd_table[fd].desock)
    {
        pthread_mutex_lock(&rw_lock);
#ifdef DEBUG
        posix_print_stack_trace();
#endif
        result = internal_writev(iov, iovcnt);
        DEBUG_LOG("[%s:%d:%d] result: %d. Desocked\n", __FUNCTION__, __LINE__, gettid(), result);
        pthread_mutex_unlock(&rw_lock);
    }
    else
    {
        result = syscall_cp(SYS_writev, fd, iov, iovcnt);
    }

    DEBUG_LOG("[%s:%d:%d] End fd: %d\n", __FUNCTION__, __LINE__, gettid(), fd);
    return result;
}
