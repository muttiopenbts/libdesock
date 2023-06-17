/* The default action for libdesock is to
 * read from stdin / write to stdout
 * but this behaviour can be changed with the
 * following to functions.
 * They have to behave like glibc functions:
 * On success they must return a value >= 0 indicating
 * how many bytes have been read / written.
 * On failure they must return -1 with errno set to the
 * corresponding error.
 */

#include <unistd.h>
#include "hooks.h"
#include "syscall.h"
#include <stdio.h>
#include "desock.h"
#include <fcntl.h>
 
/* This function is called whenever a read on a network
 * connection occurs. Read from stdin instead.
 */
ssize_t hook_input (char* buf, size_t size) {
    DEBUG_LOG ("[%d] desock::hook_input(%p, %d)", gettid (), buf, size);
    return syscall_cp(SYS_read, STDIN_FILENO, buf, size);
}

/* This function is called whenever a write on a network
 * connection occurs. Write to stdout instead.
 */
ssize_t hook_output (char* buf, size_t size) {
#ifdef DEBUG
    DEBUG_LOG ("[%d] desock::hook_output(%p, %d) DEBUG write to STDOUT_FILENO\n", gettid (), buf, size);
    return syscall_cp(SYS_write, STDOUT_FILENO, buf, size);
#else
    DEBUG_LOG ("[%d] desock::hook_output(%p, %d) No DEBUG. Nothing written to an fd.\n", gettid (), buf, size);
    return (ssize_t) size;
#endif
}
