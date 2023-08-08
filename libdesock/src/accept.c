#define _GNU_SOURCE
#include <sys/socket.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>

#include <stdlib.h>
#include <fcntl.h>

#include <time.h>

#include "syscall.h"
#include "desock.h"

#include <sys/mman.h>


/* Purpose is for help in debugging.
 */
void
get_desocks(void) {
    DEBUG_LOG ("[%d] desock::get_desocks Printing desock fd_table size: %d\n", gettid (), sizeof(fd_table));
    for (size_t i = 0; i < FD_TABLE_SIZE; i++)
    {
        if (fd_table[i].desock > 0) {
            DEBUG_LOG ("[%d] desock::get_desocks fd:%d, desock:%d, epfd: %d, listening: %d, notified: %d\n", 
                gettid (), i, fd_table[i].desock, fd_table[i].epfd, fd_table[i].listening, fd_table[i].notified);
        }
    }
}

/* Taken from https://www.geeksforgeeks.org/generating-random-number-range-c/
   Generates and prints 'count' random
   numbers in range [lower, upper].
 */
void
get_random(int* num,int lower, int upper)
{
    srand(time(0));
    *num = (rand() % (upper - lower + 1)) + lower;
    DEBUG_LOG (" get_random = %d\n", *num);
}

/* Generate a new fd based on a previous network socket fd.
 * Increment the globally highest fd.
 * TODO: Rewrite all of this function to encompass (de|in)crements
 * @param[1]    fd  File descripter id. Can be any valid fd, but the
 *              intent is that the fd should have been obtained from a 
 *              network socket(). In the case of a server, the fd passed
 *              to listen() 
 */
int
get_next_fd_incr(int fd) {
    int new_fd = 0;

    // dup() on socket fd ensures that any getsock() type calls on our fake socket, work correctly.
    new_fd = syscall (SYS_dup, fd);
    //new_fd = memfd_create("desock", 0);

    if (new_fd < 0) {
        perror("dup");
        exit(EXIT_FAILURE);
    }

    // Is this the base case when max_fd doesn't have initial value?
    // Ensure that we don't return a fd that conflicts with std(in|out|err)
    if (max_fd < 2) {
        max_fd = 3;
        DEBUG_LOG(" get_next_fd_incr cond1 max_fd = %d\n", max_fd);
    }

    // Increment global file descriptor value and return this new value.
    if (new_fd > max_fd) {
        max_fd = new_fd;
        DEBUG_LOG(" get_next_fd_incr cond2 max_fd = %d\n", max_fd);
    }
    else {
        // Do nothing since last recorded fd is greater than the last generated fd from memfd_create()
    }
    
    DEBUG_LOG(" get_next_fd_incr %d = dup(%d)\n", new_fd, fd);

    DEBUG_LOG(" get_next_fd_incr = %d return\n", new_fd);
    return new_fd;
}

/*
 * @param[in]   fd      Listening socket fd.
 * @return      new_fd  File descriptor to be used for read/write with remote peer.  
 */
static int internal_accept (int fd, struct sockaddr* restrict addr, socklen_t * restrict len, int flag) {
    /*  On success, these system calls return a file descriptor for the accepted socket.
        Non-desock listeners will get real accept() connection fd.
        accept() is usually expected to be called after listen() and in non-blocking mode it doesn't indicate a remote
        connection has occured yet.
        Desocked accept() will return a fake fd. Caller will call read() and hook will write whatever
        is read from stdin.
     */
    DEBUG_LOG ("[%s:%d:%d] (%d, %p, %p, %d) fam: %d\n", __FUNCTION__, __LINE__, gettid (), fd, addr, len, flag, fd_table[fd].domain);

    get_desocks();

    if (VALID_FD(fd) && fd_table[fd].desock && DESOCK_FD_V4(fd))
    {
        DEBUG_LOG ("[%s:%d:%d] Desocketing\n", __FUNCTION__, __LINE__, gettid ());

        if (accept_block) {
            DEBUG_LOG ("[%s:%d:%d] going to block until close(). Desocketing\n", __FUNCTION__, __LINE__, gettid ());

            int sem_value = 0;
            if (sem_getvalue(&sem, &sem_value) == 0) {
                DEBUG_LOG ("[%s:%d:%d] calling sem_wait(%p), sem_value: %d\n", __FUNCTION__, __LINE__, gettid (), sem, sem_value);
            } else {
                DEBUG_LOG ("[%s:%d:%d] calling sem_wait(%p) sem_getvalue() failed\n", __FUNCTION__, __LINE__, gettid (), sem);
            }

            sem_wait (&sem);
        }
        else
        {
            DEBUG_LOG ("[%s:%d:%d] not blocked but setting block flag for next check\n", __FUNCTION__, __LINE__, gettid ());
            accept_block = 1;
        }

        int new_fd = 0;
        new_fd = get_next_fd_incr(fd);

        if (new_fd == -1 || !VALID_FD (new_fd)) {
            // Return if dup on fd failed.
            DEBUG_LOG (" = -1\n");
            return -1;
        }

        // Erase any existing fd entry for the duplicate fd, and set members.
        clear_fd_table_entry (new_fd);
        fd_table[new_fd].domain = fd_table[fd].domain;
        fd_table[new_fd].desock = 1; // This flag ensures that read/write will be redirected from std(in|out)

        // This isn't the listen(), bind() socket fd. This comes into play with epoll_wait() and read() to stdin.
        fd_table[new_fd].listening = 0;

        // TODO: verify if socket stub needs changing.
        fill_remote_sockaddr (fd, addr, len);

        DEBUG_LOG (" new_fd: %d\n", new_fd);

        accept_on_socket(new_fd, fd);

        return new_fd;
    }
    else
    {
        DEBUG_LOG ("[%s:%d:%d] No desocketing\n", __FUNCTION__, __LINE__, gettid ());
        return socketcall_cp (accept4, fd, addr, len, flag, 0, 0);
    }
}

visible int accept (int fd, struct sockaddr* restrict addr, socklen_t * restrict len) {
    int new_fd;

    DEBUG_LOG("[%d] desock::accept(%d, %p, %d).\n", gettid(), fd, addr, len);

    new_fd = internal_accept(fd, addr, len, 0);

    return new_fd;
}

visible int accept4 (int fd, struct sockaddr* restrict addr, socklen_t * restrict len, int flg) {
    return internal_accept (fd, addr, len, flg);
}
