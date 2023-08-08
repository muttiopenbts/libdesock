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

#define _GNU_SOURCE
#include <unistd.h>
#include "hooks.h"
#include "syscall.h"
#include <stdio.h>
#include "desock.h"
#include <fcntl.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <link.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdbool.h>
#include "fsm.h"

/* Attempt to implement stateful fuzzing.
 * Use writing to sockets as a means to help transition a state machine.
 */
static ssize_t
statefull_write(char *buf, size_t count) {
    int offset = 0;

    if (desock_state != NULL) {
        DEBUG_LOG ("[%s:%d] Start count: %d\n", __FUNCTION__, __LINE__, count);
        if (is_start_state()) {
            if (is_end_state(desock_state)) {
                // Only one state so keep buf and offset as is.
                DEBUG_LOG ("[%s:%d] buf: '%s', count: %d\n", __FUNCTION__, __LINE__, buf, count);
                offset += hook_input((char *) buf, count);
                DEBUG_LOG ("[%s:%d] buf: '%s', count: %d\n", __FUNCTION__, __LINE__, buf, count);
            }
            else {
                DEBUG_LOG ("[%s:%d] count: %d\n", __FUNCTION__, __LINE__, count);
                /* First state.
                 * On this call, suck the max amount of bytes from stdin and store into user defined end state.
                 */
                if (is_end_processed(desock_state)) {
                    if (count > 0 && count <= MAX_PROTO_BYTES) {
                        /* Caller is expecting hardcoded bytes from stored state, and we must return 
                        * num of bytes specified by caller.
                        */
                        offset = get_current_state_resp_bytes_and_incr(buf, count);
                        DEBUG_LOG ("[%s:%d] offset: %d, count: %d\n", __FUNCTION__, __LINE__, offset, count);
                    }
                }
                else{ // More bytes remaining start state's resp bytes
                    offset += hook_input((char *) buf, MAX_PROTO_BYTES);
                    DEBUG_LOG ("[%s:%d] offset: %d\n", __FUNCTION__, __LINE__, offset);
                    /* We're at the first state and data arrived. Need to store these bytes for later.
                    * Store read buffer data into final state resp_bytes, replace buf bytes with 
                    * current state resp_bytes, and update offset.
                    */
                    if (count > 0 && count <= MAX_PROTO_BYTES) {
                        set_state_resp_bytes(desock_state, buf, offset);
                        /* Caller is expecting hardcoded bytes from stored state, and we must return 
                        * num of bytes specified by caller.
                        */
                        offset = get_current_state_resp_bytes_and_incr(buf, count);
                        DEBUG_LOG ("[%s:%d] offset: %d, count: %d\n", __FUNCTION__, __LINE__, offset, count);
                    }
                }
            }
        }
        else if (is_end_state(desock_state)) {
            offset = get_state_resp_bytes(desock_state, buf, count);
            DEBUG_LOG ("[%s:%d] offset: %d, count: %d\n", __FUNCTION__, __LINE__, offset, count);
        }
        else if (is_transition_state(desock_state)) {
            offset = get_current_state_resp_bytes_and_incr(buf, count);
            DEBUG_LOG ("[%s:%d] offset: %d, count: %d\n", __FUNCTION__, __LINE__, offset, count);
        }
        else { // FSM states have completed. Just wait for data on stdin
            offset += hook_input((char *) buf, count);
            DEBUG_LOG ("[%s:%d] offset: %d, count: %d\n", __FUNCTION__, __LINE__, offset, count);
        }
        // END
    }
    else { // Caller doesn't want fsm fuzzing mode
        offset += hook_input((char *) buf, count);
        DEBUG_LOG ("[%s:%d] offset: %d, count: %d\n", __FUNCTION__, __LINE__, offset, count);
    }

    uint hex_str_sz = (offset * 2) + 1;
    char hex_str[hex_str_sz];
    get_hex_str(hex_str, buf, hex_str_sz);

    DEBUG_LOG ("[%s:%d] End offset: %d, buf: %s, errno: %d\n", __FUNCTION__, __LINE__, offset, hex_str, errno);

    return offset;
}

pid_t spc_fork(void);

typedef struct
{
    FILE *read_fd;
    FILE *write_fd;
    pid_t child_pid;
} SPC_PIPE;

SPC_PIPE *spc_popen(const char *path, char *const argv[], char *const envp[])
{
    int stdin_pipe[2], stdout_pipe[2];
    SPC_PIPE *p;

    if (!(p = (SPC_PIPE *)malloc(sizeof(SPC_PIPE))))
        return 0;
    p->read_fd = p->write_fd = 0;
    p->child_pid = -1;

    if (pipe(stdin_pipe) == -1)
    {
        free(p);
        return 0;
    }
    if (pipe(stdout_pipe) == -1)
    {
        close(stdin_pipe[1]);
        close(stdin_pipe[0]);
        free(p);
        return 0;
    }

    if (!(p->read_fd = fdopen(stdout_pipe[0], "r")))
    {
        close(stdout_pipe[1]);
        close(stdout_pipe[0]);
        close(stdin_pipe[1]);
        close(stdin_pipe[0]);
        free(p);
        return 0;
    }
    if (!(p->write_fd = fdopen(stdin_pipe[1], "w")))
    {
        fclose(p->read_fd);
        close(stdout_pipe[1]);
        close(stdin_pipe[1]);
        close(stdin_pipe[0]);
        free(p);
        return 0;
    }

    if ((p->child_pid = spc_fork()) == -1)
    {
        fclose(p->write_fd);
        fclose(p->read_fd);
        close(stdout_pipe[1]);
        close(stdin_pipe[0]);
        free(p);
        return 0;
    }

    if (!p->child_pid)
    {
        /* this is the child process */
        close(stdout_pipe[0]);
        close(stdin_pipe[1]);
        if (stdin_pipe[0] != 0)
        {
            dup2(stdin_pipe[0], 0);
            close(stdin_pipe[0]);
        }
        if (stdout_pipe[1] != 1)
        {
            dup2(stdout_pipe[1], 1);
            close(stdout_pipe[1]);
        }
        execve(path, argv, envp);
        exit(127);
    }

    close(stdout_pipe[1]);
    close(stdin_pipe[0]);
    return p;
}

int spc_pclose(SPC_PIPE *p)
{
    int status;
    pid_t pid = 0;

    if (p->child_pid != -1)
    {
        do
        {
            pid = waitpid(p->child_pid, &status, 0);
        } while (pid == -1 && errno == EINTR);
    }
    if (p->read_fd)
        fclose(p->read_fd);
    if (p->write_fd)
        fclose(p->write_fd);
    free(p);
    if (pid != -1 && WIFEXITED(status))
        return WEXITSTATUS(status);
    else
        return (pid == -1 ? -1 : 0);
}

pid_t spc_fork(void)
{
    pid_t childpid;

    if ((childpid = fork()) == -1)
        return -1;

    /* Reseed PRNGs in both the parent and the child */
    /* See Chapter 11 for examples */

    /* If this is the parent process, there's nothing more to do */
    if (childpid != 0)
        return childpid;

    /* This is the child process */
    // spc_sanitize_files();   /* Close all open files.  See Recipe 1.1 */
    // spc_drop_privileges(1); /* Permanently drop privileges.  See Recipe 1.3 */

    return 0;
}

/* This function is called whenever a read on a network
 * connection occurs. Read from stdin instead.
 * Note: If 1st byte of read data is linefeed or carriage return character,
 * this function will return 0, no data.
 */
ssize_t hook_input(char *buf, size_t size)
{
    DEBUG_LOG("[%s:%d] desock::hook_input(%p, %d)\n", __FUNCTION__, __LINE__, buf, size);
    int count = syscall_cp(SYS_read, STDIN_FILENO, buf, size);

    // Interactive session with desocket needs to be able to detect when client wishes to disconnect.
    if (buf[0] == 10 || buf[0] == 13) // NLF, NL, CR
    {
        return 0; // Caller should realize there is no data and likely close() fd.
    }

    return count;
}

/* This function is called whenever a write on a network
 * connection occurs. Write to stdout instead.
 */
ssize_t hook_output(char *buf, size_t size)
{
    uint hex_str_sz = (size * 2) + 1;
    char hex_str[hex_str_sz];
    get_hex_str(hex_str, buf, hex_str_sz);

    DEBUG_LOG("[%s:%d] buf: %s, size: %d\n", __FUNCTION__, __LINE__, hex_str, size);
    // If caller is sending data to socket fd, determine if state machine should transition
    set_seen_state_transition(buf, size);
    
    return (ssize_t)size;
}

visible ssize_t hook_func(char *fake)
{
    DEBUG_LOG("[%s:%d] fake function hook.\n", __FUNCTION__, __LINE__);
    return 1;
}

// ref: https://stackoverflow.com/questions/19451791/get-loaded-address-of-a-elf-binary-dlopen-is-not-working-as-expected
uint64_t get_image_base(void)
{
    struct link_map *lm = dlopen(NULL, RTLD_NOW);
    return (uint64_t)lm->l_addr;
}

static void emit_jump_to_address(uint64_t address, uint64_t jump_destination)
{
    long page_size = sysconf(_SC_PAGESIZE);
    void *aligned_address = (void *)(address & ~(page_size - 1));
    if (mprotect(aligned_address, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) < 0)
    {
        perror("mprotect");
        return;
    }
    *(uint16_t *)(address + 0x0) = 0xb848;           // mov rax, Iv
    *(uint64_t *)(address + 0x2) = jump_destination; // mov rax, jump_destination
    *(uint16_t *)(address + 0xa) = 0xe0ff;           // jmp rax
    if (mprotect(aligned_address, page_size, PROT_READ | PROT_EXEC) < 0)
    {
        perror("mprotect");
        return;
    }
}

void end_patcher() {
    printf("END PATCHER\n");
}

void patcher(void) {
    DEBUG_LOG("[%s:%d] Patcher for fake function hook.\n", __FUNCTION__, __LINE__);

    uint64_t target;

    target = get_image_base();
    /* $ nm target|grep my_func
     * 000000000000166a T my_func
     */
    uint64_t target_func = target + 0x000000000000166a; // RVA
    printf("[!] targeted function is at %p\n", (void const *)target_func);
    printf("[!] new function is at %p\n", (void const *)&hook_func);
    DEBUG_LOG("[%s:%d] target: %x, target_func: %x, hook_func: %x.\n", __FUNCTION__, __LINE__, (void *)target, target_func, hook_func);
    emit_jump_to_address(target_func, (uint64_t)&hook_func);
}

/* Take from https://reverseengineering.stackexchange.com/questions/20395/how-do-i-go-about-overriding-a-function-internally-defined-in-a-binary-on-linux
 * TODO: Make hooked functionality user configurable during run time via config.
 * TODO: Replace hardcoded hooked function address.
 */
__attribute__((constructor)) 
void autorun(void) {
    // Disabled for now. TODO: Implement pid file creation to indicate run state
    if (false) {
        patcher();
    }
}