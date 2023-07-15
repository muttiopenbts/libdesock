#define __USE_GNU
#define GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <semaphore.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>

#include <arpa/inet.h>
#include <unistd.h>

#include "syscall.h"
#include "desock.h"
#include "proto.h"
#include <fcntl.h>

//TODO: Populate values from env variables
const struct sockaddr_in stub_sockaddr_in = {
    // TODO: make configurable at runtime or build
    .sin_family = AF_INET,
    .sin_port = 53764, // 53764 = 1234, 45824 = 179
    .sin_addr.s_addr = 0x100007f
};

//TODO: Populate values from env variables
const struct sockaddr_in stub_local_sockaddr_in = {
    // TODO: make configurable at runtime or build
    .sin_family = AF_INET,
    .sin_port = 53764, // 53764 = 1234, 45824 = 179
    .sin_addr.s_addr = 0x100007f
};

//TODO: Populate values from env variables
const struct sockaddr_in stub_remote_sockaddr_in = {
    // TODO: make configurable at runtime or build
    .sin_family = AF_INET,
    .sin_port = 45824, // 53764 = 1234, 45824 = 179
    .sin_addr.s_addr = 0x100007f
};

const struct sockaddr_in6 stub_sockaddr_in6 = {
    .sin6_family = AF_INET6,
    .sin6_port = 54020, // 54020 = htons(1235)
    .sin6_flowinfo = 0,
    .sin6_addr.s6_addr = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
    .sin6_scope_id = 0
};

/* Highest file descriptor number seen so far */
int max_fd = 0;

/* Indicates whether the next call to accept() should block or not */
int accept_block = 1;

/* Table that holds metadata about desocketed file descriptors */
struct fd_entry fd_table[FD_TABLE_SIZE];

/* Semaphore for synchronization of the connection pool in multi-threaded
   applications.
 */

sem_t sem;

/* Whitelist for ports that should only be desocketed.
 * Configured via environment variable DESOCK_PORT_LOCAL
 */
unsigned long desock_port_local = 0;

/* Port that will be used when required for desocketed syscalls.
 * Configured via environment variable DESOCK_PORT_REMOTE
 */
unsigned long desock_port_remote = 0;

/* Configured via environment variable DESOCK_LOCALIPV4.
 * e.g. "111.111.111.111\0"
 */
char desock_localipv4[MAX_IPV4_LEN + 1];

/* Configured via environment variable DESOCK_REMOTEIPV4.
 * e.g. "111.111.111.111\0"
 */
char desock_remoteipv4[MAX_IPV4_LEN + 1];

/* Given an fd that is being desocketed fill the given sockaddress structure
   with the right sockaddr stub from above.
 */
void fill_sockaddr (int fd, struct sockaddr* addr, socklen_t * addr_len) {
    if (addr && addr_len) {
        switch (fd_table[fd].domain) {
        case AF_INET:{
                struct sockaddr_in* ptr = (struct sockaddr_in *) addr;
                ptr->sin_family = AF_INET;
                if (*addr_len >= sizeof (struct sockaddr_in)) {
                    // TODO: Maybe set port to original fd port
                    ptr->sin_port = htons(desock_port_local);
                    ptr->sin_addr = stub_sockaddr_in.sin_addr;
                    // desock_localipv4 user configurable via env var
                    ptr->sin_addr.s_addr = inet_addr(desock_localipv4);

                    *addr_len = sizeof(struct sockaddr_in);
                }
                break;
            }

        case AF_INET6:{
                *addr_len = MIN (*addr_len, sizeof (stub_sockaddr_in6));
                memcpy (addr, &stub_sockaddr_in6, *addr_len);
                break;
            }

        default:{
                _error ("desock::fill_sockaddr(): Invalid domain %d\n", fd_table[fd].domain);
            }
        }
    }
}

/* Test validity of ip v4 string format.
 * Taken from https://stackoverflow.com/questions/791982/determine-if-a-string-is-a-valid-ipv4-address-in-c
 */
unsigned int
is_valid_ip_address(char *ip_address)
{
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ip_address, &(sa.sin_addr));
    return result != 0;
}

// Convert a struct sockaddr address to a string, IPv4 and IPv6:
// Taken from https://gist.github.com/jkomyno/45bee6e79451453c7bbdc22d033a282e
char *
get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen)
{
    switch(sa->sa_family) {
        case AF_INET:
            inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr),
                    s, maxlen);
            break;

        case AF_INET6:
            inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr),
                    s, maxlen);
            break;

        default:
            strncpy(s, "Unknown AF", maxlen);
            return NULL;
    }

    return s;
}

/* Read user defined ip v4 address to set on de-socketed fd.
 */
void
set_desock_localipv4(void) {
    char *p_tmp;

    if (( p_tmp = getenv( "DESOCK_LOCALIPV4" )) != NULL ) {
        strncpy( desock_localipv4, p_tmp, MAX_IPV4_LEN ); //Save last element for null
        desock_localipv4[MAX_IPV4_LEN] = '\0';
        // Check if valid port range
        if (!(is_valid_ip_address(desock_localipv4))) {
            fprintf( stderr, "DESOCK_LOCALIPV4 bad format. %s.\n", p_tmp);
            fprintf( stderr, "Exiting.\n");
            exit(EXIT_FAILURE);
        }
    }
    else {
        fprintf( stderr, "No DESOCK_LOCALIPV4 variable set.\n");
        fprintf( stderr, "Exiting.\n");
        exit(EXIT_FAILURE);
    }
}


/* Read user defined state fsm fuzzing.
 */
void
set_desock_state(void) {
    char *p_tmp;

    if (( p_tmp = getenv( "DESOCK_STATE" )) != NULL ) {
        strncpy( desock_state, p_tmp, MAX_STATE_ID -1 ); //Save last element for null
        desock_state[MAX_STATE_ID -1] = '\0';

        /* Initilize statelist */
        init_state_list(desock_state);

        /* Validate state exists */
        if (is_valid_state(desock_state) != true) {
            fprintf( stderr, "DESOCK_STATE bad format. %s.\n", p_tmp);
            fprintf( stderr, "Exiting.\n");
            exit(EXIT_FAILURE);
        }
    }
}

/* Read user defined ip v4 address to set on de-socketed fd.
 * This ip address represents the remote peer's address. 
 * e.g. Desocketing a server the peer would be the client's ip.
 */
void
set_desock_remoteipv4(void) {
    char *p_tmp;

    if (( p_tmp = getenv( "DESOCK_REMOTEIPV4" )) != NULL ) {
        strncpy( desock_remoteipv4, p_tmp, MAX_IPV4_LEN ); //Save last element for null
        desock_remoteipv4[MAX_IPV4_LEN] = '\0';
        // Check if valid port range
        if (!(is_valid_ip_address(desock_localipv4))) {
            fprintf( stderr, "DESOCK_REMOTEIPV4 bad format. %s.\n", p_tmp);
            fprintf( stderr, "Exiting.\n");
            exit(EXIT_FAILURE);
        }
    }
    else {
        fprintf( stderr, "No DESOCK_REMOTEIPV4 variable set.\n");
        fprintf( stderr, "Exiting.\n");
        exit(EXIT_FAILURE);
    }
}

/* Read user defined port number to desock. Whitelist.
 */
void
set_desock_port_local(void) {
    #define MAX_PORT_LEN 6 // 65535, len is 5 + 1 (for null)
    // Server port number we want to hook.
    char port[MAX_PORT_LEN]  = "";
    char *p_tmp;

    if (( p_tmp = getenv( "DESOCK_PORT_LOCAL" )) != NULL ) {
        strncpy( port, p_tmp, MAX_PORT_LEN-1 );           // Save a copy for our use.
        desock_port_local = strtoul(port, NULL, 10);
        
        // Check if valid port range
        if (!(desock_port_local > 0 && desock_port_local <= 65535)) {
            fprintf( stderr, "DESOCK_PORT_LOCAL out of valid range. %s.\n", p_tmp);
            fprintf( stderr, "Exiting.\n");
            exit(EXIT_FAILURE);
        }
    }
    else {
        fprintf( stderr, "No DESOCK_PORT_LOCAL variable set.\n");
        fprintf( stderr, "Exiting.\n");
        exit(EXIT_FAILURE);
    }
}

/* Read user defined port number to desock. Whitelist.
 */
void
set_desock_port_remote(void) {
    #define MAX_PORT_LEN 6 // 65535, len is 5 + 1 (for null)
    // Server port number we want to hook.
    char port[MAX_PORT_LEN]  = "";
    char *p_tmp;

    if (( p_tmp = getenv( "DESOCK_PORT_REMOTE" )) != NULL ) {
        strncpy( port, p_tmp, MAX_PORT_LEN-1 );           // Save a copy for our use.
        desock_port_remote = strtoul(port, NULL, 10);
        
        // Check if valid port range
        if (!(desock_port_remote > 0 && desock_port_remote <= 65535)) {
            fprintf( stderr, "DESOCK_PORT_REMOTE out of valid range. %s.\n", p_tmp);
            fprintf( stderr, "Exiting.\n");
            exit(EXIT_FAILURE);
        }
    }
    else {
        fprintf( stderr, "No DESOCK_PORT_REMOTE variable set.\n");
        fprintf( stderr, "Exiting.\n");
        exit(EXIT_FAILURE);
    }
}

/* Initialize some system-wide variables.
 * TODO: need to incorporate new variables.
 */
void
init_variables (void) {
    set_desock_port_local();
    set_desock_port_remote();
    set_desock_localipv4();
    set_desock_remoteipv4();
    set_desock_state();
}

/* Given an fd that is being desocketed fill the given sockaddress structure
   with the right sockaddr stub from above.
 */
void fill_remote_sockaddr (int fd, struct sockaddr* addr, socklen_t * addr_len) {
    if (addr && addr_len) {
        switch (fd_table[fd].domain) {
        case AF_INET:{
                struct sockaddr_in* ptr = (struct sockaddr_in *) addr;
                ptr->sin_family = AF_INET;
                if (*addr_len >= sizeof (struct sockaddr_in)) {
                    // TODO: Maybe set port to original fd port
                    ptr->sin_port = htons(desock_port_remote);
                    ptr->sin_addr = stub_remote_sockaddr_in.sin_addr;

                    ptr->sin_addr.s_addr = inet_addr(desock_remoteipv4);

                    *addr_len = sizeof(struct sockaddr_in);
                }
                break;
            }

        case AF_INET6:{
                *addr_len = MIN (*addr_len, sizeof (stub_sockaddr_in6));
                memcpy (addr, &stub_sockaddr_in6, *addr_len);
                break;
            }

        default:{
                _error ("desock::fill_sockaddr(): Invalid domain %d\n", fd_table[fd].domain);
            }
        }
    }
}

/* Given an fd that is being desocketed fill the given sockaddress structure
   with the right sockaddr stub from above.
 */
void fill_local_sockaddr (int fd, struct sockaddr* addr, socklen_t * addr_len) {
    if (addr && addr_len) {
        switch (fd_table[fd].domain) {
            case AF_INET:{
                struct sockaddr_in* ptr = (struct sockaddr_in *) addr;
                ptr->sin_family = AF_INET;
                if (*addr_len >= sizeof (struct sockaddr_in)) {
                    // TODO: Maybe set port to original fd port
                    ptr->sin_port = htons(desock_port_local);
                    ptr->sin_addr = stub_local_sockaddr_in.sin_addr;

                    ptr->sin_addr.s_addr = fd_table[fd].address;

                    *addr_len = sizeof(struct sockaddr_in);
                }
                break;
            }

            case AF_INET6:{
                *addr_len = MIN (*addr_len, sizeof (stub_sockaddr_in6));
                memcpy (addr, &stub_sockaddr_in6, *addr_len);
                break;
            }

            default:{
                _error ("desock::fill_sockaddr(): Invalid domain %d\n", fd_table[fd].domain);
            }
        }
    }
}

#ifdef DEBUG
void _debug (char* fmt_string, ...) {
    va_list args;
    va_start (args, fmt_string);
    vfprintf (stderr, fmt_string, args);
    va_end (args);
    fflush (stderr);
}
#endif

void _error (char* fmt_string, ...) {
    va_list args;
    va_start (args, fmt_string);
    vfprintf (stderr, fmt_string, args);
    va_end (args);
    abort ();
}

static int
make_fd_non_blocking(int fd)
{
    int flags, s;

    flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
    {
        perror("fcntl");
        return -1;
    }

    flags |= O_NONBLOCK;
    s = fcntl(fd, F_SETFL, flags);
    if (s == -1)
    {
        perror("fcntl");
        return -1;
    }

    return 0;
}

/* This function runs before the hooked applications main().
 */
__attribute__ ((constructor))
void desock_init (void) {
    printf("Running libdesock...\n");

    if (sem_init(&sem, 1, MAX_CONNS) == -1)
    {
        _error ("desock::error: sem_init failed\n");
    }
    // Initialize global variables that are user configurable.
    init_variables();
}

const char elf_interpreter[] __attribute__ ((section (".interp"))) = INTERPRETER;


/* Keep track of which non server fds have been notified for an event.
 * Were interested in fds generated after an accept().
 */
void
accept_on_socket(int afd, int sfd){
    fd_table[afd].notified = sfd;
}

void desock_main (void) {
    printf ("libdesock.so: A fast desocketing library built for fuzzing\n" "\n" "This library can desock\n" "    servers = "
#ifdef DESOCK_BIND
            "yes"
#else
            "no"
#endif
            "\n" "    clients = "
#ifdef DESOCK_CONNECT
            "yes"
#else
            "no"
#endif
            "\n\n" "Compilation options:\n" "    - DEBUG = "
#ifdef DEBUG
            "yes"
#else
            "no"
#endif
            "\n" "    - MAX_CONNS = %d\n" "    - FD_TABLE_SIZE = %d\n" "    - ARCH = %s\n" "\n" "Use this with LD_PRELOAD=libdesock.so on a network application\n" "or with AFL_PRELOAD=libdesock.so when fuzzing with AFL.\n", MAX_CONNS, FD_TABLE_SIZE, DESOCKARCH);

    exit (0);
}

#ifdef DEBUG
visible void clear_fd_table_entry (int idx) {
    fd_table[idx].epfd = -1;
    fd_table[idx].desock = 0;
    fd_table[idx].listening = 0;
    fd_table[idx].notified = 0;
}

visible int _debug_instant_fd (int listening) {
    int fd = syscall (SYS_dup, 0);

    if (fd < 0 || !VALID_FD (fd)) {
        return -1;
    }

    fd_table[fd].desock = 1;
    fd_table[fd].listening = (listening != 0);
    return fd;
}

visible void _debug_get_fd_table_entry (int idx, struct fd_entry* dst) {
    memcpy (dst, &fd_table[idx], sizeof (struct fd_entry));
}
#endif
