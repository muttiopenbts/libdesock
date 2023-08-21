#define _GNU_SOURCE
#define __USE_GNU
#include <unistd.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "syscall.h"
#include "desock.h"
#include "peekbuffer.h"
#include "hooks.h"
#include "fsm.h"

#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>

// #define SLEEP_TIMER 110 // inconsistent results
#define SLEEP_TIMER 120 // milliseconds

struct thread_data
{
    int thread_id;
    char *buf;
    struct iovec *iov;
    int count;
    long *result;
};

/* Attempt to implement stateful fuzzing.
 * Use writing to sockets as a means to help transition a state machine.
 */
static ssize_t
statefull_read(char *buf, size_t count)
{
    DEBUG_LOG("[%s:%d] Start count: %d\n", __FUNCTION__, __LINE__, count);

    int offset = 0;

    if (desock_state != NULL)
    {
        if (is_start_state())
        {
            if (is_end_state(desock_state))
            {
                // Only one state so keep buf and offset as is.
                DEBUG_LOG("[%s:%d] buf: '%s', count: %d\n", __FUNCTION__, __LINE__, buf, count);
                offset += hook_input((char *)buf, count);
                DEBUG_LOG("[%s:%d] buf: '%s', count: %d\n", __FUNCTION__, __LINE__, buf, count);
            }
            else
            {
                DEBUG_LOG("[%s:%d] count: %d\n", __FUNCTION__, __LINE__, count);
                /* First state.
                 * On this call, suck the max amount of bytes from stdin and store into user defined end state.
                 */
                if (is_end_processed(desock_state))
                {
                    if (count > 0 && count <= MAX_PROTO_BYTES)
                    {
                        /* Caller is expecting hardcoded bytes from stored state, and we must return
                         * num of bytes specified by caller.
                         */
                        offset = get_current_state_resp_bytes_and_incr((unsigned char *)buf, count);
                        DEBUG_LOG("[%s:%d] offset: %d, count: %d\n", __FUNCTION__, __LINE__, offset, count);
                    }
                }
                else
                { // More bytes remaining start state's resp bytes
                    offset += hook_input((char *)buf, MAX_PROTO_BYTES);
                    DEBUG_LOG("[%s:%d] offset: %d\n", __FUNCTION__, __LINE__, offset);
                    /* We're at the first state and data arrived. Need to store these bytes for later.
                     * Store read buffer data into final state resp_bytes, replace buf bytes with
                     * current state resp_bytes, and update offset.
                     */
                    if (count > 0 && count <= MAX_PROTO_BYTES)
                    {
                        set_state_resp_bytes(desock_state, buf, offset);
                        /* Caller is expecting hardcoded bytes from stored state, and we must return
                         * num of bytes specified by caller.
                         */
                        offset = get_current_state_resp_bytes_and_incr((unsigned char *)buf, count);
                        DEBUG_LOG("[%s:%d] offset: %d, count: %d\n", __FUNCTION__, __LINE__, offset, count);
                    }
                }
            }
        }
        else if (is_end_state(desock_state))
        {
            offset = get_state_resp_bytes(desock_state, (unsigned char *)buf, count);
            DEBUG_LOG("[%s:%d:%d] offset: %d, count: %d\n", __FUNCTION__, __LINE__, gettid(), offset, count);
        }
        else if (is_transition_state(desock_state))
        {
            // TODO: fsm not working without sleep. Need to remove this or make user configurable.
            msleep(SLEEP_TIMER);

            offset = get_current_state_resp_bytes_and_incr((unsigned char *)buf, count);
            DEBUG_LOG("[%s:%d:%d] offset: %d, count: %d\n", __FUNCTION__, __LINE__, gettid(), offset, count);
        }
        else
        { // FSM states have completed. End/exit process. This will help speed up fuzzer from waiting for timeout.
            DEBUG_LOG("[%s:%d:%d] offset: %d, count: %d\n", __FUNCTION__, __LINE__, gettid(), offset, count);
            // raise(SIGTERM);
            pthread_exit(NULL);
            // END
        }
    }
    else
    { // Caller doesn't want fsm fuzzing mode
        offset += hook_input((char *)buf, count);
        DEBUG_LOG("[%s:%d] offset: %d, count: %d\n", __FUNCTION__, __LINE__, offset, count);
    }

    uint hex_str_sz = (offset * 2) + 1;
    char hex_str[hex_str_sz];
    get_hex_str(hex_str, buf, hex_str_sz);

    DEBUG_LOG("[%s:%d:%d] End offset: %d, buf: %s, errno: %d\n", __FUNCTION__, __LINE__, gettid(), offset, hex_str, errno);

    return offset;
}

static long internal_readv(struct iovec *iov, int iov_count, int *full, int peek, int offset)
{
    DEBUG_LOG("[%s:%d] Start iov: %p, iov_count: %d.\n", __FUNCTION__, gettid(), iov, iov_count);
    int read_total = 0;

    if (full)
    {
        *full = 1;
    }

    // Cycle through every iov buffer
    for (int i = 0; i < iov_count; ++i)
    {
        int read_num = 0;

        if (peek)
        {
            read_num = peekbuffer_cp(iov[i].iov_base, iov[i].iov_len, offset);
            offset += read_num;
        }
        else
        {
            if (peekbuffer_size() > 0)
            {
                read_num = peekbuffer_mv(iov[i].iov_base, iov[i].iov_len);
            }

            if (read_num < iov[i].iov_len)
            {
                DEBUG_LOG("[%s:%d] iov[i].iov_len: %d, iov[i].iov_len - read_num: %d\n", __FUNCTION__, __LINE__, iov[i].iov_len, iov[i].iov_len - read_num);
                errno = 0;
                read_num += statefull_read((char *)iov[i].iov_base + read_num, iov[i].iov_len - read_num);

                DEBUG_LOG("[%s:%d:%d] i: %d, read_num: %d\n", __FUNCTION__, __LINE__, gettid(), i, read_num);

                if (errno)
                {
                    DEBUG_LOG("[%s:%d] End errno: %d\n", __FUNCTION__, __LINE__, errno);
                    return -1;
                }
            }
        }

        read_total += read_num;

        if (read_num < iov[i].iov_len)
        {
            if (full)
            {
                *full = 0;
            }

            break;
        }
    }

    DEBUG_LOG("[%s:%d] End read_total: %d\n", __FUNCTION__, gettid(), read_total);
    return read_total;
}

void state_handler(void)
{
    if (desock_state != NULL)
    {
        DEBUG_LOG("[%s] desock_state %s\n", __FUNCTION__, desock_state);
        if (is_valid_state(desock_state))
        {
            DEBUG_LOG("[%s] desock_state, is valid state.\n", __FUNCTION__);
        }
    }
}

/* Calling read() and expecting to get data from stdin requires piping your data to the process.
    e.g. # clear; echo -e 'MYFUZZEDDATA' |LD_PRELOAD=libdesock.so ./echo_server-epoll 179
 */
visible ssize_t read(int fd, void *buf, size_t count)
{
    // nul out buffer to ensure no tainted results.
    memset(buf, '\0', count);

    DEBUG_LOG("[%s:%d:%d] Start read(%d, %p, %lu)\n", __FUNCTION__, __LINE__, gettid(), fd, buf, count);

    /* TODO: Disable reading from certain file descriptors that can interfere with tests. e.g. stdin.
     * Make this user configurable.
     */
    if (VALID_FD(fd) && fd_table[fd].desock)
    {
        DEBUG_LOG("[%d] read(%d, %p, %lu) Desock\n", gettid(), fd, buf, count);

        int offset = 0;

        if (peekbuffer_size() > 0)
        {
            offset = peekbuffer_mv(buf, count);
        }

        DEBUG_LOG("[%d:%s:%d] read offset: %d\n", gettid(), __FUNCTION__, __LINE__, offset);

        if (offset < count)
        {
            errno = 0;

            offset += statefull_read((char *)buf + offset, count - offset);

            DEBUG_LOG(" buf: '%s'\n", buf);
            DEBUG_LOG("[%d:%s:%d] read Desock hook_input offset: %d, errno: %d\n", gettid(), __FUNCTION__, __LINE__, offset, errno);

            if (errno)
            {
                DEBUG_LOG(" = -1\n");
                return -1;
            }
        }
        DEBUG_LOG("[%s:%d] End offset: %d Desocked\n", __FUNCTION__, __LINE__, offset);

        return offset;
    }
    else if (fd == STDIN_FILENO)
    { // TODO: Make this user configurable.
        DEBUG_LOG("[%s:%d] End read matched fd: %d Desocked\n", __FUNCTION__, __LINE__, fd);
        return 0;
    }
    else
    {
        DEBUG_LOG("[%s:%d] End read(%d, %p, %lu) No desock\n", __FUNCTION__, __LINE__, fd, buf, count);
        return syscall_cp(SYS_read, fd, buf, count);
    }
}

static ssize_t internal_recv(int fd, char *buf, size_t len, int flags)
{
    size_t buflen = peekbuffer_size();
    int offset = 0;

    if (flags & MSG_PEEK)
    {
        long delta = len - buflen;

        if (delta > 0 && peekbuffer_read(delta) == -1)
        {
            return -1;
        }

        return peekbuffer_cp(buf, len, 0);
    }
    else if (buflen > 0)
    {
        offset = peekbuffer_mv(buf, len);
    }

    if (offset < len)
    {
        errno = 0;
        offset += hook_input(buf + offset, len - offset);

        if (errno)
        {
            return -1;
        }
    }

    return offset;
}

visible ssize_t recvfrom(int fd, void *buf, size_t len, int flags, struct sockaddr *restrict addr, socklen_t *alen)
{
    int result = 0;
    DEBUG_LOG("[%d] desock::recvfrom(%d, %p, %lu, %d, %p, %p)\n", gettid(), fd, buf, len, flags, addr, alen);

    if (VALID_FD(fd) && fd_table[fd].desock)
    {
        DEBUG_LOG("[%d] desock::recvfrom. Desock\n", gettid());

        /* Server calling on a fd from accept() */
        fill_sockaddr(fd, addr, alen);

        result = internal_recv(fd, buf, len, flags);
        DEBUG_LOG(" = %d\n", result);
        return result;
    }
    else
    {
        result = socketcall_cp(recvfrom, fd, buf, len, flags, addr, alen);
        DEBUG_LOG("[%d] desock::recvfrom no desock\n", gettid());
        DEBUG_LOG(" = %d\n", result);
        return result;
    }
}

visible ssize_t recv(int fd, void *buf, size_t len, int flags)
{
    if (VALID_FD(fd) && fd_table[fd].desock)
    {
        int r = internal_recv(fd, buf, len, flags);
        DEBUG_LOG("[%d] desock::recv(%d, %p, %lu, %d) = %d\n", gettid(), fd, buf, len, flags, r);
        return r;
    }
    else
    {
        DEBUG_LOG("[%d] desock::recv(%d, %p, %lu, %d)\n", gettid(), fd, buf, len, flags);
        return socketcall_cp(recvfrom, fd, buf, len, flags, NULL, NULL);
    }
}

visible ssize_t recvmsg(int fd, struct msghdr *msg, int flags)
{
    if (VALID_FD(fd) && fd_table[fd].desock)
    {
        DEBUG_LOG("[%d] desock::recvmsg(%d, %p, %d)", gettid(), fd, msg, flags);

        if (flags & MSG_PEEK)
        {
            size_t total_length = 0;

            for (int i = 0; i < msg->msg_iovlen; ++i)
            {
                total_length += msg->msg_iov[i].iov_len;
            }

            long delta = total_length - peekbuffer_size();

            if (delta > 0 && peekbuffer_read(delta) == -1)
            {
                DEBUG_LOG(" = -1\n");
                return -1;
            }
        }

        msg->msg_flags = 0;

        fill_sockaddr(fd, msg->msg_name, &msg->msg_namelen);

        int r = internal_readv(msg->msg_iov, msg->msg_iovlen, NULL, flags & MSG_PEEK, 0);
        DEBUG_LOG(" = %d\n", r);
        return r;
    }
    else
    {
        DEBUG_LOG("[%d] desock::recvmsg(%d, %p, %d)", gettid(), fd, msg, flags);
        return socketcall_cp(recvmsg, fd, msg, flags, 0, 0, 0);
    }
}

visible int recvmmsg(int fd, struct mmsghdr *msgvec, unsigned int vlen, int flags, struct timespec *timeout)
{
    if (VALID_FD(fd) && fd_table[fd].desock)
    {
        DEBUG_LOG("[%d] desock::recvmmsg(%d, %p, %d, %d, %p)", gettid(), fd, msgvec, vlen, flags, timeout);

        int i;
        int offset = 0;

        if (flags & MSG_PEEK)
        {
            size_t total_length = 0;

            for (i = 0; i < vlen; ++i)
            {
                for (int j = 0; j < msgvec[i].msg_hdr.msg_iovlen; ++j)
                {
                    total_length += msgvec[i].msg_hdr.msg_iov[j].iov_len;
                }
            }

            long delta = total_length - peekbuffer_size();

            if (delta > 0 && peekbuffer_read(delta) == -1)
            {
                DEBUG_LOG(" = -1\n");
                return -1;
            }
        }

        for (i = 0; i < vlen; ++i)
        {
            int full = 0;

            msgvec[i].msg_hdr.msg_flags = 0;

            fill_sockaddr(fd, msgvec[i].msg_hdr.msg_name, &msgvec[i].msg_hdr.msg_namelen);

            msgvec[i].msg_len = internal_readv(msgvec[i].msg_hdr.msg_iov, msgvec[i].msg_hdr.msg_iovlen, &full, flags & MSG_PEEK, offset);

            if (msgvec[i].msg_len == -1)
            {
                DEBUG_LOG(" = -1\n");
                return -1;
            }

            offset += msgvec[i].msg_len;

            if (!full)
            {
                break;
            }
        }

        int r = (i == vlen || i == 0) ? i : (i + 1);
        DEBUG_LOG(" = %d\n", r);
        return r;
    }
    else
    {
        DEBUG_LOG("[%d] desock::recvmmsg(%d, %p, %d, %d, %p)", gettid(), fd, msgvec, vlen, flags, timeout);
        return syscall_cp(SYS_recvmmsg, fd, msgvec, vlen, flags, timeout);
    }
}

void *thread_internal_readv(void *threadarg)
{
    DEBUG_LOG("[%s:%d:%d] Start\n", __FUNCTION__, __LINE__, gettid());

    struct thread_data *my_data;
    my_data = (struct thread_data *)threadarg;

    my_data->result = (long *)internal_readv(my_data->iov, my_data->count, NULL, 0, 0);
    DEBUG_LOG("[%s:%d:%d] End my_data->result: %d\n", __FUNCTION__, __LINE__, gettid(), my_data->result);
    pthread_exit(NULL);
}

/* @return  Number of bytes read or negative number for error.
 */
visible ssize_t readv(int fd, struct iovec *iov, int count)
{
    DEBUG_LOG("[%s:%d:%d] Start (%d, %p, %d)\n", __FUNCTION__, __LINE__, gettid(), fd, iov, count);

    if (VALID_FD(fd) && fd_table[fd].desock)
    {
        struct thread_data args;

        long *read = 0;
        args.iov = iov;
        args.count = count;
        args.result = read;

        pthread_t ptid;

        // Creating a new thread
        if (pthread_create(&ptid, NULL, &thread_internal_readv, &args) != 0)
        {
            perror("pthread_create() error");
            exit(1);
        }

        pthread_join(ptid, NULL);

        DEBUG_LOG("[%s:%d:%d] END Desocked fd: %d, result: %d\n", __FUNCTION__, __LINE__, gettid(), fd, args.result);
        return (ssize_t)args.result;
    }
    else
    {
        DEBUG_LOG("[%s:%d:%d] END fd: %d\n", __FUNCTION__, __LINE__, gettid(), fd);
        return syscall_cp(SYS_readv, fd, iov, count);
    }
}
