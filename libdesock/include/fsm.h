/* Template implementaiton for a statefull protocol. Use to assist with fuzzing.
 */
#ifndef FSM_H
#define FSM_H

#include <semaphore.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <stdbool.h>

#define MAX_STATE_ID 128
#define MAX_STATES 6
#define MAX_PROTO_BYTES 4096

typedef struct proto_state_def {
    /* Unique string to identify the state */
    char id[MAX_STATE_ID];

    /* Optional bool Flag that fsm state has been used.*/
    bool is_processed;

    /* bool. Keep track of which state we are currently in.  */
    bool is_current_state;

    /* Previous state pointer */
    struct proto_state_def *prev;
   
    /* bool Flag that fsm state related bytes have been seen in socket call.
     * e.g. server has replied to a client/state message. Ready now for client to send bytes from read().
     */
    bool search_bytes_seen;

    /* Raw network bytes to help determine state. */
    char search_bytes[MAX_PROTO_BYTES];
    /* Number of actual used bytes. */
    unsigned int search_bytes_sz;

    /* Raw network bytes to write/send to network daemon. */
    unsigned char resp_bytes[MAX_PROTO_BYTES];
    /* Number of actual used bytes. */
    unsigned int resp_bytes_sz;

} state_def;

extern state_def state_list[MAX_STATES];
extern char desock_state[MAX_STATE_ID];

extern state_def *state_def_new();
extern bool is_valid_state(char *state);
extern void init_state_list(char *state);
extern bool is_current_state(char *state);
extern bool is_end_state(char *state);
extern bool is_start_state();
extern bool is_transition_state(char *state);
extern bool set_state_resp_bytes(char *state, char *resp_bytes, size_t buf_size);
extern ssize_t get_state_resp_bytes(char *state, unsigned char *buf, size_t buf_size);
extern ssize_t get_current_state_resp_bytes_and_incr(unsigned char *buf, size_t buf_size);
extern void set_seen_state_transition(unsigned char *buf, size_t buf_size);
extern bool is_processed(char *state);
extern bool is_end_processed(char *state);
extern bool is_start_processed();
ssize_t get_current_state_idx();

#endif /* FSM_H */