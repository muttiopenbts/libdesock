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


#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>

static long internal_readv (struct iovec* iov, int iov_count, int* full, int peek, int offset) {
    DEBUG_LOG ("[%d] desock::internal_readv iov: %p, iov_count: %d.\n", gettid (), iov, iov_count);
    int read_total = 0;

    if (full) {
        *full = 1;
    }

    // Cycle through every iov buffer
    for (int i = 0; i < iov_count; ++i) {
        int read_num = 0;

        if (peek) {
            read_num = peekbuffer_cp (iov[i].iov_base, iov[i].iov_len, offset);
            offset += read_num;
        } else {
            if (peekbuffer_size () > 0) {
                read_num = peekbuffer_mv (iov[i].iov_base, iov[i].iov_len);
            }

            if (read_num < iov[i].iov_len) {
                errno = 0;
                read_num += hook_input((char *) iov[i].iov_base + read_num, iov[i].iov_len - read_num);

                DEBUG_LOG ("[%d] desock::internal_readv i: %d, read_num: %d\n", gettid (), i, read_num);

                if (errno) {
                    DEBUG_LOG ("[%d] desock::internal_readv returning errno: %d\n", gettid (), errno);
                    return -1;
                }
            }
        }

        read_total += read_num;

        if (read_num < iov[i].iov_len) {
            if (full) {
                *full = 0;
            }

            break;
        }
    }

    DEBUG_LOG ("[%d] desock::internal_readv read_total: %d\n", gettid (), read_total);
    return read_total;
}

/* Calling read() and expecting to get data from stdin requires piping your data to the process.
    e.g. # clear; echo -e 'MYFUZZEDDATA' |LD_PRELOAD=libdesock.so ./echo_server-epoll 179
 */
visible ssize_t read (int fd, void* buf, size_t count) {
    DEBUG_LOG ("[%d] desock::read(%d, %p, %lu)\n", gettid (), fd, buf, count);

    /* TODO: Disable reading from certain file descriptors that can interfere with tests. e.g. stdin.
     * Make this user configurable.
     */ 
    if (VALID_FD (fd) && fd_table[fd].desock) {
        DEBUG_LOG ("[%d] desock::read(%d, %p, %lu) Desock\n", gettid (), fd, buf, count);

        int offset = 0;

        if (peekbuffer_size () > 0) {
            offset = peekbuffer_mv (buf, count);
        }

        DEBUG_LOG ("[%d] desock::read offset: %d\n", gettid (), offset);

        if (offset < count) {
            errno = 0;
            offset += hook_input((char *) buf + offset, count - offset);

            DEBUG_LOG(" buf: %s\n", buf);
            DEBUG_LOG ("[%d] desock::read Desock hook_input offset: %d, errno: %d\n", gettid (), offset, errno);

            if (errno) {
                DEBUG_LOG (" = -1\n");
                return -1;
            }
        }
#ifdef DEBUG
        sleep(2);
#endif
        DEBUG_LOG(" offset: %d\n", offset);
        return offset;
    } 
    else if (fd == STDIN_FILENO) { // TODO: Make this user configurable.
        DEBUG_LOG ("[%d] desock::read matched fd: %d Desocked\n", gettid (), fd);
        return 0;
    }
    else
    {
        DEBUG_LOG ("[%d] desock::read(%d, %p, %lu) No desock\n", gettid (), fd, buf, count);
        return syscall_cp (SYS_read, fd, buf, count);
    }
}

static ssize_t internal_recv (int fd, char* buf, size_t len, int flags) {
    size_t buflen = peekbuffer_size ();
    int offset = 0;

    if (flags & MSG_PEEK) {
        long delta = len - buflen;

        if (delta > 0 && peekbuffer_read (delta) == -1) {
            return -1;
        }

        return peekbuffer_cp (buf, len, 0);
    } else if (buflen > 0) {
        offset = peekbuffer_mv (buf, len);
    }

    if (offset < len) {
        errno = 0;
        offset += hook_input(buf + offset, len - offset);

        if (errno) {
            return -1;
        }
    }

    return offset;
}

visible ssize_t recvfrom (int fd, void* buf, size_t len, int flags, struct sockaddr* restrict addr, socklen_t * alen) {
    if (VALID_FD (fd) && fd_table[fd].desock) {
        DEBUG_LOG ("[%d] desock::recvfrom(%d, %p, %lu, %d, %p, %p)", gettid (), fd, buf, len, flags, addr, alen);

        fill_sockaddr (fd, addr, alen);

        int r = internal_recv (fd, buf, len, flags);
        DEBUG_LOG (" = %d\n", r);
        return r;
    } else {
        DEBUG_LOG ("[%d] desock::recvfrom(%d, %p, %lu, %d, %p, %p)", gettid (), fd, buf, len, flags, addr, alen);
        return socketcall_cp (recvfrom, fd, buf, len, flags, addr, alen);
    }
}

visible ssize_t recv (int fd, void* buf, size_t len, int flags) {
    if (VALID_FD (fd) && fd_table[fd].desock) {
        int r = internal_recv (fd, buf, len, flags);
        DEBUG_LOG ("[%d] desock::recv(%d, %p, %lu, %d) = %d\n", gettid (), fd, buf, len, flags, r);
        return r;
    } else {
        DEBUG_LOG ("[%d] desock::recv(%d, %p, %lu, %d)\n", gettid (), fd, buf, len, flags);
        return socketcall_cp (recvfrom, fd, buf, len, flags, NULL, NULL);
    }
}

visible ssize_t recvmsg (int fd, struct msghdr* msg, int flags) {
    if (VALID_FD (fd) && fd_table[fd].desock) {
        DEBUG_LOG ("[%d] desock::recvmsg(%d, %p, %d)", gettid (), fd, msg, flags);

        if (flags & MSG_PEEK) {
            size_t total_length = 0;

            for (int i = 0; i < msg->msg_iovlen; ++i) {
                total_length += msg->msg_iov[i].iov_len;
            }

            long delta = total_length - peekbuffer_size ();

            if (delta > 0 && peekbuffer_read (delta) == -1) {
                DEBUG_LOG (" = -1\n");
                return -1;
            }
        }

        msg->msg_flags = 0;

        fill_sockaddr (fd, msg->msg_name, &msg->msg_namelen);

        int r = internal_readv (msg->msg_iov, msg->msg_iovlen, NULL, flags & MSG_PEEK, 0);
        DEBUG_LOG (" = %d\n", r);
        return r;
    } else {
        DEBUG_LOG ("[%d] desock::recvmsg(%d, %p, %d)", gettid (), fd, msg, flags);
        return socketcall_cp (recvmsg, fd, msg, flags, 0, 0, 0);
    }
}

visible int recvmmsg (int fd, struct mmsghdr* msgvec, unsigned int vlen, int flags, struct timespec* timeout) {
    if (VALID_FD (fd) && fd_table[fd].desock) {
        DEBUG_LOG ("[%d] desock::recvmmsg(%d, %p, %d, %d, %p)", gettid (), fd, msgvec, vlen, flags, timeout);

        int i;
        int offset = 0;

        if (flags & MSG_PEEK) {
            size_t total_length = 0;

            for (i = 0; i < vlen; ++i) {
                for (int j = 0; j < msgvec[i].msg_hdr.msg_iovlen; ++j) {
                    total_length += msgvec[i].msg_hdr.msg_iov[j].iov_len;
                }
            }

            long delta = total_length - peekbuffer_size ();

            if (delta > 0 && peekbuffer_read (delta) == -1) {
                DEBUG_LOG (" = -1\n");
                return -1;
            }
        }

        for (i = 0; i < vlen; ++i) {
            int full = 0;

            msgvec[i].msg_hdr.msg_flags = 0;

            fill_sockaddr (fd, msgvec[i].msg_hdr.msg_name, &msgvec[i].msg_hdr.msg_namelen);

            msgvec[i].msg_len = internal_readv (msgvec[i].msg_hdr.msg_iov, msgvec[i].msg_hdr.msg_iovlen, &full, flags & MSG_PEEK, offset);

            if (msgvec[i].msg_len == -1) {
                DEBUG_LOG (" = -1\n");
                return -1;
            }

            offset += msgvec[i].msg_len;

            if (!full) {
                break;
            }
        }

        int r = (i == vlen || i == 0) ? i : (i + 1);
        DEBUG_LOG (" = %d\n", r);
        return r;
    } else {
        DEBUG_LOG ("[%d] desock::recvmmsg(%d, %p, %d, %d, %p)", gettid (), fd, msgvec, vlen, flags, timeout);
        return syscall_cp (SYS_recvmmsg, fd, msgvec, vlen, flags, timeout);
    }
}

/* @return  Number of bytes read or negative number for error.
 */
visible ssize_t readv (int fd, struct iovec* iov, int count) {
    DEBUG_LOG ("[%d] desock::readv(%d, %p, %d)\n", gettid (), fd, iov, count);

    if (VALID_FD (fd) && fd_table[fd].desock) {
        int read = internal_readv (iov, count, NULL, 0, 0);
        DEBUG_LOG ("[%d] desock::readv(%d, %p, %d) = %d Desocked\n", gettid (), fd, iov, count, read);
        return read;
    } else {
        DEBUG_LOG ("[%d] desock::readv(%d, %p, %d)\n", gettid (), fd, iov, count);
        return syscall_cp (SYS_readv, fd, iov, count);
    }
}
