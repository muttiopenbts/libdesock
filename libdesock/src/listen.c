#define _GNU_SOURCE
#include <sys/socket.h>
#include <unistd.h>

#include "syscall.h"
#include "desock.h"

visible int listen (int fd, int backlog) {
    /* File descriptor entry for desock should have been set during bind().
     */
    if (VALID_FD (fd) && fd_table[fd].desock) {
        DEBUG_LOG ("[%d] desock::listen(%d, %d) = 0. Desocketed\n", gettid (), fd, backlog);
        fd_table[fd].listening = 1;
        return 0;
    } else {
        return socketcall (listen, fd, backlog, 0, 0, 0, 0);
    }
}
