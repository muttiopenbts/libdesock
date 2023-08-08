#ifndef DESOCK_H
#define DESOCK_H

#include <semaphore.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <stdbool.h>

// Check that we are desocketing at least one of client or server
#ifndef DESOCK_BIND
#ifndef DESOCK_CONNECT
#error "At least one of DESOCK_CONNECT or DESOCK_BIND must be specified"
#endif
#endif

/*
If conns >= MAX_CONNS accept() will block
*/
#ifndef MAX_CONNS
#define MAX_CONNS 1
#endif

/* e.g. "111.111.111.111"
 * Doesn't include string terminating null
 */
#define MAX_IPV4_LEN 15

extern sem_t sem;
extern unsigned long desock_port_local;
extern unsigned long desock_port_remote;
extern char desock_localipv4[MAX_IPV4_LEN + 1];
extern char desock_remoteipv4[MAX_IPV4_LEN + 1];

#ifdef DEBUG
void _debug (char*, ...);
#define DEBUG_LOG(...) _debug(__VA_ARGS__);
#else
#define DEBUG_LOG(...)
#endif

void fill_sockaddr (int, struct sockaddr*, socklen_t*);
void fill_local_sockaddr (int, struct sockaddr*, socklen_t*);
void fill_remote_sockaddr (int, struct sockaddr*, socklen_t*);
void _error (char*, ...);
unsigned int is_valid_ip_address (char *);
char* get_ip_str(const struct sockaddr*, char*, size_t);
extern void get_hex_str(char*, char*, size_t);

struct fd_entry {
    /* Optional Internet address. */
    uint32_t address;

    /* Optional port number for network sockets */
    unsigned int port;

    /* information passed to socket() */
    int domain;
    
    /* flag whether to desock this fd */
    int desock;
    
    /* flag whether this is the server socket */
    int listening;
    
    /* epoll stuff */
    int epfd;
    struct epoll_event ep_event;
    struct epoll_event *ptr_ev;

    int notified; // Track whether we have notified caller via epoll_wait()
};

#ifndef FD_TABLE_SIZE
#define FD_TABLE_SIZE 1024
#endif

extern struct fd_entry fd_table[FD_TABLE_SIZE];
extern int accept_block;
extern int max_fd;
extern const struct sockaddr_in stub_sockaddr_in;
extern const struct sockaddr_in stub_local_sockaddr_in;
extern const struct sockaddr_in stub_remote_sockaddr_in;
extern const struct sockaddr_in6 stub_sockaddr_in6;
extern const struct sockaddr_un stub_sockaddr_un;

#define VALID_FD(x) (0 <= (x) && (x) < FD_TABLE_SIZE)

#define DESOCK_FD(x) (fd_table[(x)].domain == AF_INET || fd_table[(x)].domain == AF_INET6)

#define DESOCK_DOMAIN(x) (x == AF_INET || domain == AF_INET6)

#define DESOCK_DOMAIN_v4(x) (x == AF_INET)

// Check if fd is an IPv4 family type
#define DESOCK_FD_V4(x) (fd_table[(x)].domain == AF_INET)

#ifdef DEBUG
void clear_fd_table_entry(int);
#else
inline void clear_fd_table_entry (int idx) {
    fd_table[idx].port = 0;
    fd_table[idx].address = 0;
    fd_table[idx].epfd = -1;
    fd_table[idx].desock = 0;
    fd_table[idx].listening = 0;
    fd_table[idx].notified = 0;
}
#endif

#define MIN(x, y) ((x) < (y) ? (x) : (y))

#define visible __attribute__ ((visibility ("default")))

#endif /* DESOCK_H */

void accept_on_socket(int afd, int sfd);