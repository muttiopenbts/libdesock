#define _GNU_SOURCE
#include <sys/epoll.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <semaphore.h>
#include <unistd.h>

#include "desock.h"
#include "syscall.h"

/*
 * @return 0 for success, -1 failed.
 */
visible int epoll_create(int size)
{
    int r = __syscall_ret(__syscall(SYS_epoll_create1, 0));
    DEBUG_LOG("[%d] desock::epoll_create(%d) = %d\n", gettid(), size, r);
    return r;
}

/*
 * @return 0 for success, -1 failed.
 */
visible int epoll_create1(int flags)
{
    int r = __syscall_ret(__syscall(SYS_epoll_create1, flags));
    DEBUG_LOG("[%d] desock::epoll_create1(%d) = %d\n", gettid(), flags, r);
    return r;
}

/* Any fd in fd_table with desock flag will never reach epoll_ctl and thus
 * never have a real epoll_wait() call.
 * Goal is to store epoll data in fd_table and when epoll_wait() is called, we can
 * fake epoll_wait() return on interested fds in fd_table.
 *
 * @param[1]    fd  File descriptor obtained from epoll_create().
 * @param[2]    op  Integer representing operation types that will trigger notification, EPOLLIN, etc
 * @param[3]    fd  File descriptor of interest and will be add|del|mod from epoll.
 * @param[4]    ev  epoll_event struct that contains the types of events the caller is interested in
 *                  being notified on.
 */
visible int epoll_ctl(int efd, int op, int fd2, struct epoll_event *ev)
{
    DEBUG_LOG("[%s:%d:%d] Start (%d, %d, %d, %p)\n", __FUNCTION__, __LINE__, gettid(), efd, op, fd2, ev);
    int result = 0;

    if (VALID_FD(fd2) && fd_table[fd2].desock)
    {
        if (op == EPOLL_CTL_ADD || op == EPOLL_CTL_MOD)
        {
            // Caller wants to add or modify an epoll fd list of events.
            DEBUG_LOG("[%s:%d:%d] ADD|MOD", __FUNCTION__, __LINE__, gettid());
            fd_table[fd2].epfd = efd;
            fd_table[fd2].ptr_ev = ev;
            fd_table[fd2].ep_event.events = ev->events;
            fd_table[fd2].ep_event.data = ev->data;
        }
        else if (op == EPOLL_CTL_DEL)
        {
            DEBUG_LOG("[%s:%d:%d] DEL", __FUNCTION__, __LINE__, gettid());
            fd_table[fd2].epfd = -1;
        }

        if (fd_table[fd2].desock)
        {
            // Any entries in fd_table flagged for desock, will never be added to an epoll.
            DEBUG_LOG(" Desocked result: %d\n", result);
            return result;
        }
    }

    result = syscall(SYS_epoll_ctl, efd, op, fd2, ev);
    DEBUG_LOG(" result: %d\n", result);
    return result;
}

/* Check if stdin has data ready for reading.
 * @returns         uint    1 = true, stdin has data, 0 false.
 */
uint stdin_has_data(void)
{
#define STDIN_HAS_DATA_TIMEOUT 5
    DEBUG_LOG("[%d] desock::stdin_has_data.\n", gettid());

    fd_set rfds;
    struct timeval tv;
    int retval;

    /* Watch stdin (fd 0) to see when it has input. */
    FD_ZERO(&rfds);
    FD_SET(STDIN_FILENO, &rfds);
    /* Wait up to n seconds. */
    tv.tv_sec = STDIN_HAS_DATA_TIMEOUT;
    tv.tv_usec = 0;

    // Call real syscall select()
    retval = syscall_cp(SYS_select, 1, &rfds, NULL, NULL, &tv);
    /* Don't rely on the value of tv now! */

    if (retval > 0)
    {
        DEBUG_LOG("[%d] desock::stdin_has_data. Data is available now. retval: %d\n", gettid(), retval);
        return 1;
        /* FD_ISSET(0, &rfds) will be true. */
    }
    else
    {
        DEBUG_LOG("[%d] desock::stdin_has_data. retval: %d. No data within %d seconds.\n", gettid(), retval, STDIN_HAS_DATA_TIMEOUT);
        return 0;
    }

    return 0;
}

/* @return  1 if we find a file descriptor associated with sfd (server file descriptor) param.
 */
uint is_listener_notified(int sfd)
{
    DEBUG_LOG("[%s:%d] sfd: %d, max_fd: %d\n", __FUNCTION__, __LINE__, sfd, max_fd);
    for (int fd_idx = 0; fd_idx <= max_fd; fd_idx++)
    {
        if (fd_table[fd_idx].notified == sfd)
        {
            return 1;
        }
    }

    return 0;
}

int get_event_fd(struct epoll_event ev)
{
    return ev.data.fd;
}

/* This function is intended to block epoll_wait() on desock flagged fds and fake the caller
 * into thinking the fd is ready.
 * This function will block if we are desocketing a listening fd. Will unblock when close is called
 * on a desocketed read fd.
 * The two types of fd we are interested are ones related to bind() because the caller wants to accept()
 * and the other is the fd related to accept() and caller wants to read().
 * TODO: Add additional verification that stdin has data in buffer before returning an epoll_wait
 * for an fd that will be used for an accept() call.
 *
 * @return  return_ready_cnt    The number of file descriptors
 *                              ready for the requested I/O, or zero if no file descriptor became
 *                              ready during the requested timeout. 0 will cause calling function
 *                              to call real epoll_wait() syscall. This might not be what is intended
 *                              for desocking.
 *                              If we have fds associated with efd, then always return positive cnt.
 * @return ev                   Callers epoll_event will be populated with the fds that are ready.
 */
static int internal_epoll_wait(int efd, struct epoll_event *ev, int maxevents)
{
    DEBUG_LOG("[%s:%d:%d] Start internal_epoll_wait(%d, %p, %d) max_fd: %d \n", __FUNCTION__, __LINE__, gettid(), efd, ev, maxevents, max_fd);

    /* Will only increment if efd is associated with an fd that is flagged
     * desock, and !listening. This should be an fd returned from accept() and caller
     * wants to call read()
     */
    int return_ready_cnt = 0;
    int server_sock = -1;
    int server_sock_ready_cnt = 0;   // Increment on every fd with listen flag. But block if mutux locked.
    int accepted_sock_ready_cnt = 0; // Increment on every fd with listen flag. But block if mutux locked.

    accept_block = 0; // accept() will not block on sem_wait()

    for (int fd_idx = 0; fd_idx <= max_fd && return_ready_cnt < maxevents; ++fd_idx)
    {
        // Iterate over every fd_table entry and match if the entry is flagged to desock and has been
        // added to this epoll object.
        if (fd_table[fd_idx].desock && fd_table[fd_idx].epfd == efd)
        {
            DEBUG_LOG("[%s:%d] Found sock_fd: %d match epfd: %d.\n", __FUNCTION__, __LINE__, fd_idx, efd);
            // Check if we have a server fd associated with the epoll fd. This would have been set during bind().

            if (fd_table[fd_idx].listening)
            {
                // Only notify listener events that haven't already been notified.
                DEBUG_LOG("[%s:%d] sfd: %d, is listening.\n", __FUNCTION__, __LINE__, fd_idx);
                if (!is_listener_notified(fd_idx))
                {
                    DEBUG_LOG("[%s:%d] No notification sent.\n", __FUNCTION__, gettid(), fd_idx);
                    // Record highest numbered fd with server_sock.
                    server_sock = fd_idx;
                    server_sock_ready_cnt++;

                    DEBUG_LOG("[%s:%d] Server server_sock: %d, with return_ready_cnt: %d\n", __FUNCTION__, gettid(), server_sock, return_ready_cnt);
                    DEBUG_LOG("[%s:%d] ev fd: %d\n", __FUNCTION__, __LINE__, server_sock, get_event_fd(ev[return_ready_cnt]));

                    // Update caller's events with server's associated events from fd_table.
                    ev[return_ready_cnt].events = fd_table[server_sock].ep_event.events;
                    ev[return_ready_cnt].events &= EPOLLIN; // Caller will see fd is ready for recv
                    ev[return_ready_cnt].data = fd_table[server_sock].ep_event.data;
                    // Increment so that caller knows that listen fd is ready and caller can transition to accept()
                    ++return_ready_cnt;

                    // The fd_table events entry was marked EPOLLONESHOT, prevent this fd_entry matching any epoll fds.
                    if (fd_table[server_sock].ep_event.events & EPOLLONESHOT)
                    {
                        fd_table[server_sock].epfd = -1;
                    }
                }
                else
                {
                    // listening socket has an associated accept() fd.
                    // TODO: Make sure epoll_wait() intercepter knows that real epoll_wait() must not be called.
                    DEBUG_LOG("[%s:%d:%d] Server fd_idx: %d has accept() fd. Stop epoll_wait()\n", __FUNCTION__, __LINE__, gettid(), fd_idx);
                    accept_block = 1;
                }
            }
            else
            {
                DEBUG_LOG("[%s:%d] fd_idx: %d, notified: %d\n", __FUNCTION__, __LINE__, fd_idx, fd_table[fd_idx].notified);
                // Update events that have notified flag set. Such as fds returned from accept() and are waiting to call read() and close()
                if (fd_table[fd_idx].notified)
                {
                    // This isn't a server fd but it is marked for de-socketing. Just update returning ev with fd_table ev data.
                    DEBUG_LOG("[%s:%d] sfd: %d, isn't listening.\n", __FUNCTION__, gettid(), fd_idx);
                    ev[return_ready_cnt].events = fd_table[fd_idx].ep_event.events;
                    ev[return_ready_cnt].events &= (EPOLLIN | EPOLLOUT);
                    ev[return_ready_cnt].data = fd_table[fd_idx].ep_event.data;
                    ++return_ready_cnt;
                    accepted_sock_ready_cnt++;

                    // The fd_table events entry was marked EPOLLONESHOT, prevent this fd_entry matching any epoll fds.
                    if (fd_table[fd_idx].ep_event.events & EPOLLONESHOT)
                    {
                        DEBUG_LOG("[%s:%d] erase epfd: %d on sfd: %d\n", __FUNCTION__, gettid(), fd_table[fd_idx].epfd, fd_idx);
                        fd_table[fd_idx].epfd = -1;
                    }
                }
            }
        }
    }

    DEBUG_LOG("[%s:%d] server_sock: %d, return_ready_cnt: %d.\n", __FUNCTION__, gettid(), server_sock, return_ready_cnt);
    // If we have at least one fd marked as a server under this epoll then we're going to attempt to block
    // until sem_post() called in hooked close() if the fd is flagged desock and !listening.
    if (server_sock_ready_cnt > 0 && return_ready_cnt < maxevents)
    {
        // Stay below maxevents because caller specified this value.
        int sem_value = 0;
        if (sem_getvalue(&sem, &sem_value) == 0)
        {
            DEBUG_LOG("[%s:%d] calling sem_trywait(%p), sem_value: %d\n", __FUNCTION__, gettid(), sem, sem_value);
        }
        else
        {
            DEBUG_LOG("[%s:%d] calling sem_trywait(%p) failed\n", __FUNCTION__, gettid(), sem);
        }

        DEBUG_LOG("[%s:%d] Entering sem_wait(), accepted_sock_ready_cnt: %d\n", __FUNCTION__, gettid(), accepted_sock_ready_cnt);
        sem_wait(&sem);
        DEBUG_LOG("[%s:%d] Exit sem_wait()\n", __FUNCTION__, gettid());

        // Block here until stdin is ready with data to read.
        // This doesn't have the desired effect for all desock scenarios.
        while (stdin_has_data() == 0)
        {
            DEBUG_LOG("[%s:%d] Stdin no data.\n", __FUNCTION__, gettid());
        }
    }

    if (accept_block && accepted_sock_ready_cnt < 1)
    {
        /* This is to indicate to calling funcion that they should not make any subsequent calls to real syscall.
         * TODO: Better solution for preventing multiple listening fd being returned would be to
         * intercept and remove the interesting fds from the real epoll_wait()
         */
        DEBUG_LOG("[%s:%d:%d] End returning: %d\n", __FUNCTION__, __LINE__, gettid(), -2);
        return -2;
    }

    DEBUG_LOG("[%s:%d:%d] End returning: %d\n", __FUNCTION__, __LINE__, gettid(), server_sock_ready_cnt + accepted_sock_ready_cnt);
    return server_sock_ready_cnt + accepted_sock_ready_cnt;
}

visible int epoll_pwait(int fd, struct epoll_event *ev, int cnt, int to, const sigset_t *sigs)
{
    DEBUG_LOG("[%d] desock::epoll_pwait(%d, %p, %d, %d, %p)", gettid(), fd, ev, cnt, to, sigs);

    int ret = internal_epoll_wait(fd, ev, cnt);
    if (ret)
    {
        DEBUG_LOG(" = %d\n", ret);
        return ret;
    }
    else
    {
        ret = __syscall_ret(__syscall(SYS_epoll_pwait, fd, ev, cnt, to, sigs));
        DEBUG_LOG(" = %d\n", ret);
        return ret;
    }
}

/* All epoll_wait() calls are hooked and passed to internal_epoll_wait() logic.
 * epoll_wait() returns the number of file descriptors ready for the requested I/O,
 * and the caller will expect param ev to contain information from the ready
 * list about file descriptors in the interest list that have some
 * events available.
 * Any fds flagged as desock in fd_table will never make actual epoll_wait()
 * syscall, and internal_epoll_wait will return to caller to notify that fd from accept() is ready
 * for recv.
 *
 * @params[1]   fd  Epoll fd that was obtained from epoll_create()
 * @params[2]   ev  Pointer that the caller will expect the function to fill with the fd ready for action.
 */
visible int epoll_wait(int fd, struct epoll_event *ev, int maxevents, int to)
{
    DEBUG_LOG("[%s:%d:%d] Start (%d, %p, %d, %d)\n", __FUNCTION__, __LINE__, gettid(), fd, ev, maxevents, to);

    int ret = internal_epoll_wait(fd, ev, maxevents);

    if (ret == -2)
    {
        // -2 indicates that internal_epoll_wait() has an fd from bind() and doesn't want caller to call accept()
        DEBUG_LOG("[%s:%d] ret: %d\n", __FUNCTION__, __LINE__, ret);
        ret = 0;
    }
    else if (ret == 0)
    {
        DEBUG_LOG("[%s:%d] ret: %d\n", __FUNCTION__, __LINE__, ret);
        ret = __syscall_ret(__syscall(SYS_epoll_pwait, fd, ev, maxevents, to, 0));
    }

    DEBUG_LOG("[%s:%d:%d] End ret: %d\n", __FUNCTION__, __LINE__, gettid(), ret);
    return ret;
}

visible int epoll_pwait2(int epfd, struct epoll_event *events, int maxevents, const struct timespec *timeout, const sigset_t *sigmask)
{
    DEBUG_LOG("[%d] desock::epoll_pwait2(%d, %p, %d, %p, %p)", gettid(), epfd, events, maxevents, timeout, sigmask);

    int ret = internal_epoll_wait(epfd, events, maxevents);
    if (ret)
    {
        DEBUG_LOG(" = %d\n", ret);
        return ret;
    }
    else
    {
        errno = ENOSYS;
        DEBUG_LOG(" = -1\n");
        return -1;
    }
}
