#define _GNU_SOURCE
#include <sys/epoll.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <semaphore.h>
#include <unistd.h>

#include "desock.h"
#include "syscall.h"

#ifdef DEBUG
/*
 * @return 0 for success, -1 failed.
 */
visible int epoll_create (int size) {
    int r = __syscall_ret (__syscall (SYS_epoll_create1, 0));
    DEBUG_LOG ("[%d] desock::epoll_create(%d) = %d\n", gettid (), size, r);
    return r;
}

/*
 * @return 0 for success, -1 failed.
 */
visible int epoll_create1 (int flags) {
    int r = __syscall_ret (__syscall (SYS_epoll_create1, flags));
    DEBUG_LOG ("[%d] desock::epoll_create1(%d) = %d\n", gettid (), flags, r);
    return r;
}
#endif

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
visible int epoll_ctl (int efd, int op, int fd2, struct epoll_event* ev) {
    if (VALID_FD (fd2) && fd_table[fd2].desock) {
        DEBUG_LOG ("[%d] desock::epoll_ctl(%d, %d, %d, %p)\n", gettid (), efd, op, fd2, ev);

        if (op == EPOLL_CTL_ADD || op == EPOLL_CTL_MOD) {
            // Caller wants to add or modify an epoll fd list of events.
            DEBUG_LOG ("[%d] desock::epoll_ctl(%d, %d, %d, %p) ADD|MOD", gettid (), efd, op, fd2, ev);
            fd_table[fd2].epfd = efd;
            fd_table[fd2].ptr_ev = ev;
            fd_table[fd2].ep_event.events = ev->events;
            fd_table[fd2].ep_event.data = ev->data;
        } else if (op == EPOLL_CTL_DEL) {
            DEBUG_LOG ("[%d] desock::epoll_ctl(%d, %d, %d, %p) DEL", gettid (), efd, op, fd2, ev);
            fd_table[fd2].epfd = -1;
        }

        if (fd_table[fd2].desock) {
            // Any entries in fd_table flagged for desock, will never be added to an epoll.
            DEBUG_LOG (" Desocked = 0");
            return 0;
        }
    }

    DEBUG_LOG ("[%d] desock::epoll_ctl(%d, %d, %d, %p) Not desocked\n", gettid (), efd, op, fd2, ev);
    int r = syscall (SYS_epoll_ctl, efd, op, fd2, ev);
#ifdef DEBUG
    if (VALID_FD (fd2)) {
        DEBUG_LOG (" = %d\n", r);
    }
#endif
    return r;
}

/* This function is intended to block epoll_wait() on desock flagged fds and fake the caller
 * into thinking the fd is ready.
 * TODO: Add additional verification that stdin has data in buffer before returning an epoll_wait
 * for an fd that will be used for an accept() call.
 *
 * @return  return_ready_cnt    The number of file descriptors
 *                              ready for the requested I/O, or zero if no file descriptor became
 *                              ready during the requested timeout.
 */
static int internal_epoll_wait (int fd, struct epoll_event* ev, int cnt) {
    DEBUG_LOG ("[%d] desock::internal_epoll_wait(%d, %p, %d) max_fd: %d \n", gettid (), fd, ev, cnt, max_fd);

    int return_ready_cnt = 0;
    int server_sock = -1;

    accept_block = 0;

    for (int fd_idx = 0; fd_idx <= max_fd && return_ready_cnt < cnt; ++fd_idx) {
        // Iterate over every fd_table entry and match if the entry is flagged to desock and has been 
        // added to this epoll object.
        if (fd_table[fd_idx].desock && fd_table[fd_idx].epfd == fd) {
            DEBUG_LOG ("[%d] desock::internal_epoll_wait Found sock_fd: %d match epfd: %d.\n", gettid (), fd_idx, fd);
            // Check if we have a server fd associated with the epoll fd. This would have been set during bind().

            if (fd_table[fd_idx].listening) {
                DEBUG_LOG ("[%d] desock::internal_epoll_wait And sfd: %d, is listening.\n", gettid (), fd_idx);
                // Record highest numbered fd with server_sock.
                server_sock = fd_idx;
            } else {
                // This isn't a server fd. Just update returning ev with fd_table ev data.
                DEBUG_LOG ("[%d] desock::internal_epoll_wait And sfd: %d, isn't listening.\n", gettid (), fd_idx);
                ev[return_ready_cnt].events = fd_table[fd_idx].ep_event.events;
                ev[return_ready_cnt].events &= (EPOLLIN | EPOLLOUT);
                ev[return_ready_cnt].data = fd_table[fd_idx].ep_event.data;
                ++return_ready_cnt;

                // The fd_table events entry was marked EPOLLONESHOT, prevent this fd_entry matching any epoll fds.
                if (fd_table[fd_idx].ep_event.events & EPOLLONESHOT) {
                    DEBUG_LOG ("[%d] desock::internal_epoll_wait erase epfd: %d on sfd: %d.\n", gettid (), fd_table[fd_idx].epfd, fd_idx);
                    fd_table[fd_idx].epfd = -1;
                }
            }
        }
    }

    DEBUG_LOG("[%d] desock::internal_epoll_wait server_sock: %d, return_ready_cnt: %d.\n", gettid(), server_sock, return_ready_cnt);
    // If we have at least one fd marked as a server under this epoll then we're going to attempt to block
    // until sem_post() called in hooked close() if the fd is flagged desock and !listening.
    if (server_sock > -1 && return_ready_cnt < cnt) {
        int sem_value = 0;
        if (sem_getvalue(&sem, &sem_value) == 0) {
            DEBUG_LOG("[%d] desock::internal_epoll_wait calling sem_trywait(%p), sem_value: %d.\n", gettid(), sem, sem_value);
        } else {
            DEBUG_LOG("[%d] desock::internal_epoll_wait calling sem_trywait(%p) failed\n", gettid(), sem);
        }

        if (sem_trywait (&sem) == -1) {
            DEBUG_LOG("[%d] desock::internal_epoll_wait sem_trywait()\n", gettid());

            if (errno != EAGAIN) {
                _error ("desock::internal_epoll_wait(): sem_trywait failed\n");
            }

            if (return_ready_cnt > 0) {
                DEBUG_LOG("[%d] desock::internal_epoll_wait Going to return return_ready_cnt: %d\n", gettid(), return_ready_cnt);
                return return_ready_cnt;
            }

            DEBUG_LOG("[%d] desock::internal_epoll_wait sem_wait()\n", gettid());
            sem_wait (&sem);
        }

        DEBUG_LOG ("[%d] desock::internal_epoll_wait Server server_sock: %d, with return_ready_cnt: %d\n", gettid (), server_sock, return_ready_cnt);

        ev[return_ready_cnt].events = fd_table[server_sock].ep_event.events;
        ev[return_ready_cnt].events &= EPOLLIN;
        ev[return_ready_cnt].data = fd_table[server_sock].ep_event.data;
        ++return_ready_cnt;

        // The fd_table events entry was marked EPOLLONESHOT, prevent this fd_entry matching any epoll fds.
        if (fd_table[server_sock].ep_event.events & EPOLLONESHOT) {
            fd_table[server_sock].epfd = -1;
        }
    }

    return return_ready_cnt;
}

visible int epoll_pwait (int fd, struct epoll_event* ev, int cnt, int to, const sigset_t * sigs) {
    DEBUG_LOG ("[%d] desock::epoll_pwait(%d, %p, %d, %d, %p)", gettid (), fd, ev, cnt, to, sigs);

    int ret = internal_epoll_wait (fd, ev, cnt);
    if (ret) {
        DEBUG_LOG (" = %d\n", ret);
        return ret;
    } else {
        ret = __syscall_ret (__syscall (SYS_epoll_pwait, fd, ev, cnt, to, sigs));
        DEBUG_LOG (" = %d\n", ret);
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
visible int epoll_wait (int fd, struct epoll_event* ev, int cnt, int to) {
    DEBUG_LOG ("[%d] desock::epoll_wait(%d, %p, %d, %d)", gettid (), fd, ev, cnt, to);

    int ret = internal_epoll_wait (fd, ev, cnt);
    if (ret) {
        DEBUG_LOG (" internal_epoll_wait = %d\n", ret);
        return ret;
    } else {
        ret = __syscall_ret (__syscall (SYS_epoll_pwait, fd, ev, cnt, to, 0));
        DEBUG_LOG (" epoll_wait = %d\n", ret);
        return ret;
    }
}

visible int epoll_pwait2 (int epfd, struct epoll_event* events, int maxevents, const struct timespec* timeout, const sigset_t * sigmask) {
    DEBUG_LOG ("[%d] desock::epoll_pwait2(%d, %p, %d, %p, %p)", gettid (), epfd, events, maxevents, timeout, sigmask);

    int ret = internal_epoll_wait (epfd, events, maxevents);
    if (ret) {
        DEBUG_LOG (" = %d\n", ret);
        return ret;
    } else {
        errno = ENOSYS;
        DEBUG_LOG (" = -1\n");
        return -1;
    }
}
