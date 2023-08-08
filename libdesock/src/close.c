#define _GNU_SOURCE
#include <unistd.h>
#include <errno.h>
#include <semaphore.h>

#include "syscall.h"
#include "desock.h"

visible int close (int fd) {
    DEBUG_LOG ("[%s:%d:%d] Start close(%d)", __FUNCTION__, __LINE__, gettid (), fd);
    int r = 0;

    if (VALID_FD (fd)) {
#ifdef DEBUG
        if (fd_table[fd].desock) {
            DEBUG_LOG ("[%s:%d:%d] desock::close(%d)\n", __FUNCTION__, __LINE__, gettid (), fd);
        }
#endif

        if (fd_table[fd].desock && !fd_table[fd].listening) {
            int sem_value = 0;

            if (sem_getvalue (&sem, &sem_value) == -1) {
#ifdef DEBUG
                if (fd_table[fd].desock) {
                    DEBUG_LOG (" = -1\n");
                }
#endif
                return -1;
            }

            if (sem_value < MAX_CONNS) {
                sem_post (&sem);
            }
        }
#ifdef DEBUG
        if (fd_table[fd].desock) {
            DEBUG_LOG (" = 0\n");
        }
#endif

        clear_fd_table_entry (fd);
    }

    if (fd > 1) {
        r = __syscall_cp (SYS_close, fd);

        DEBUG_LOG ("[%s:%d:%d] desock::close(%d). Making real syscall. Result: %d\n", __FUNCTION__, __LINE__, gettid (), fd, r);

        if (r == -EINTR)
            r = 0;
    }

    return __syscall_ret (r);
}
