#define _GNU_SOURCE
#include <sys/socket.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include <time.h>

#include "syscall.h"
#include "desock.h"

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

int
get_next_fd_incr(int fd) {
    // Is this the base case when max_fd doesn't have initial value?
    // Ensure that we don't return a fd that conflicts with std(in|out|err)
    if (max_fd < 2) {
        max_fd = 3;
        DEBUG_LOG(" get_next_fd_incr cond1 max_fd = %d\n", max_fd);
    }

    // Increment global file descriptor value and return this new value.
    if (fd > max_fd) {
        max_fd = fd + 1;
        DEBUG_LOG(" get_next_fd_incr cond2 max_fd = %d\n", max_fd);
    }
    else {
        max_fd += 1;
    }
    

    DEBUG_LOG(" get_next_fd_incr = %d return\n", max_fd);
    return max_fd;
}

static int internal_accept (int fd, struct sockaddr* restrict addr, socklen_t * restrict len, int flag) {
    /*  On success, these system calls return a file descriptor for the accepted socket.
        Non-desock listeners will get real accept() connection fd.
        accept() is usually expected to be called after listen() and in non-blocking mode it doesn't indicate a remote
        connection has occured yet.
        Desocked accept() will return a fake fd. Caller will call read() and hook will write whatever
        is read from stdin.

        TODO: calling close() on fake fd fails. Need to handle gracefully if fd is fake.
     */
    get_desocks();

    if (len > 0 && addr != NULL) { 
        struct sockaddr_in *remote_sock = (struct sockaddr_in *)addr;
//        DEBUG_LOG ("[%d] desock::internal_accept(%d, %p, %p, %d) Remote:%s \n", gettid (), fd, addr, len, flag, inet_ntoa(remote_sock->sin_addr));
    } else { 
        /* no peer */ 
    }

    DEBUG_LOG ("[%d] desock::internal_accept(%d, %p, %p, %d)\n", gettid (), fd, addr, len, flag);

    if (VALID_FD(fd) && fd_table[fd].desock)
    {
        DEBUG_LOG ("[%d] desock::internal_accept(%d, %p, %p, %d) Desocketing\n", gettid (), fd, addr, len, flag);
        
        if (accept_block) {
            sem_wait (&sem);
        } else {
            accept_block = 1;
        }

        //int new_fd = syscall (SYS_dup, fd);
        //int new_fd = syscall (SYS_dup, fd);

        // Create a file for desocketed server to send network reply msgs.
        //const char* filename = "/tmp/desock-accept-fd.txt";

        // TODO: Race condition if multiple calls to open() on same file. Should check if file already open
        // or find alternative mechanism.
        //int fs_fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, 0644);
        //int new_fd = syscall (SYS_dup, fs_fd);
        int new_fd = 0;
        new_fd = get_next_fd_incr(new_fd);
        // int new_fd = fs_fd;

        //if (fs_fd == -1) {
            // Return if open() on fd failed.
        //    perror("open");
        //    exit(EXIT_FAILURE);
        //}

        //#define TEST_MSG "THIS IS A TEST FROM LIBDESOCK\n"
        //write(new_fd, TEST_MSG, sizeof(TEST_MSG));

        if (new_fd == -1 || !VALID_FD (new_fd)) {
            // Return if dup on fd failed.
            DEBUG_LOG (" = -1\n");
            return -1;
        }

        // Erase any existing fd entry for the duplicate fd, and set members.
        clear_fd_table_entry (new_fd);
//        fd_table[new_fd].domain = fd_table[fd].domain;
//        fd_table[new_fd].desock = fd_table[fd].desock;
//        fd_table[new_fd].desock = 1;
        fd_table[new_fd].domain = 0;
        fd_table[new_fd].desock = 1; // This flag ensures that read/write will be redirected from std(in|out)
        fd_table[new_fd].listening = 0;

        // TODO: verify if socket stub needs changing.
        fill_sockaddr (fd, addr, len);

        //if (new_fd + 1 > max_fd) {
        //    max_fd = new_fd + 1;
        //}

        DEBUG_LOG (" new_fd: %d\n", new_fd);
        return new_fd;
    }
    else
    {
        return socketcall_cp (accept4, fd, addr, len, flag, 0, 0);
    }
}

visible int accept (int fd, struct sockaddr* restrict addr, socklen_t * restrict len) {
    return internal_accept (fd, addr, len, 0);
}

visible int accept4 (int fd, struct sockaddr* restrict addr, socklen_t * restrict len, int flg) {
    return internal_accept (fd, addr, len, flg);
}
