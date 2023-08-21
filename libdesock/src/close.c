#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <semaphore.h>

#include "syscall.h"
#include "desock.h"
#include "fsm.h"

/* Intent is to close all fd except stdin/out/err.
 * If the fd is a socket that we are tracking, then clear its meta data too and release/decrement any locks.
 */
visible int close(int fd)
{
    DEBUG_LOG("[%s:%d:%d] Start (%d)\n", __FUNCTION__, __LINE__, gettid(), fd);
    int result = 0;

    // fd being tracked as a socket?
    if (fd_table[fd].desock)
    {
        if (!fd_table[fd].listening)
        {
            // Looking for client sockets, not daemons
            int sem_value = 0;

            if (sem_getvalue(&sem, &sem_value) == -1)
            {
                // Error with lock
                DEBUG_LOG("[%s:%d:%d] sem_value: %d\n", __FUNCTION__, __LINE__, gettid(), sem_value);
                return -1;
            }

            if (sem_value < MAX_CONNS)
            {
                DEBUG_LOG("[%s:%d:%d] sem_value: %d\n", __FUNCTION__, __LINE__, gettid(), sem_value);
                // Unlock any blocking process waiting.
                sem_post(&sem);
            }
        }

        clear_fd_table_entry(fd);
        if (desock_state != NULL)
        {
            exit(0); // TODO: Conditionally end process if user desires requests.
            /* Initilize statelist */
            // init_state_list(desock_state);
        }
    }

    // This prevent's closing stdin/out/err
    if (fd > 1)
    {
        DEBUG_LOG("[%s:%d:%d] (%d) Making real syscall. Result: %d\n", __FUNCTION__, __LINE__, gettid(), fd, result);
        result = __syscall_cp(SYS_close, fd);

        if (result == -EINTR)
            result = 0;
    }

    DEBUG_LOG("[%s:%d:%d] End (%d) Result: %d\n", __FUNCTION__, __LINE__, gettid(), fd, result);
    return __syscall_ret(result);
}
