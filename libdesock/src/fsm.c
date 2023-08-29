/* Template implementaiton for a statefull protocol. Use to assist with fuzzing.
 */
#define __USE_GNU
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/un.h>
#include <unistd.h>
#include "fsm.h"
#include "desock.h"
#include <sched.h>

state_def state_open = {
    .id = {"OPEN"},
    .is_processed = false,
    .prev = NULL, // 53764 = 1234, 45824 = 179
    .search_bytes[0] = {{0xff}, 1},
    .resp_bytes = {0x41, 0x42, 0x43, 0x44}};

state_def state_update = {
    .id = {"UPDATE"},
    .is_processed = false,
    .prev = NULL, // 53764 = 1234, 45824 = 179
    .search_bytes[0] = {{0xff}, 1},
    .resp_bytes = {0x45, 0x46, 0x47}};

/*  */
state_def state_list[MAX_STATES];

/* Configured via environment variable DESOCK_STATE.
 * e.g. "OPEN\0"
 */
char desock_state[MAX_STATE_ID] = {0};

/* Flag to indicate whether fsm states have all been processed.
 */
bool fsm_completed = false;

/* Use this initializer/constructor for state_def types.
 * Caller responsible for dealloc()
 */
state_def *state_def_new(void)
{
    state_def *my_state = malloc(sizeof(state_def));
    if (my_state == NULL)
    {
        fprintf(stderr, "Unable to allocate buffer\n");
    }
    memset(my_state->id, '\0', sizeof(MAX_STATE_ID));
    my_state->is_current_state = false;
    my_state->is_processed = false;
    my_state->resp_bytes_sz = 0;
    // Default to true. If false, this indicates that this optional feature is enabled.
    my_state->search_bytes_seen = true;

    for (int arr_size = 0; arr_size < MAX_SEARCH_BYTES; arr_size++)
    {
        state_search_def *state_search = malloc(sizeof(state_search_def));
        if (state_search == NULL)
        {
            fprintf(stderr, "Unable to allocate buffer\n");
        }

        memset(state_search, '\0', sizeof(state_search_def));
        my_state->search_bytes[arr_size] = *state_search;
    }

    return my_state;
}

/* Initialize fsm structs into data structure that will help
 * us navigate between states.
 * Pkts taken from ebgp.
 */
void init_state_list(char *state)
{
    /* Define our state objects before assigning to state_list */
    state_def *state_1 = state_def_new();
    snprintf(state_1->id, sizeof(state_1->id), "%s", "open");
    state_1->prev = NULL;
    // Hold time 3 secs.
    memcpy(state_1->resp_bytes, (char[MAX_PROTO_BYTES]){0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0xb1, 0x01, 0x04, 0x00, 0x64, 0x00, 0x03, 0x01, 0x01, 0x01, 0x02, 0x94, 0x02, 0x06, 0x01, 0x04, 0x00, 0x01, 0x00, 0x01, 0x02, 0x06, 0x01, 0x04, 0x00, 0x01, 0x00, 0x02, 0x02, 0x06, 0x01, 0x04, 0x00, 0x01, 0x00, 0x04, 0x02, 0x06, 0x01, 0x04, 0x00, 0x01, 0x00, 0x80, 0x02, 0x06, 0x01, 0x04, 0x00, 0x01, 0x00, 0x84, 0x02, 0x06, 0x01, 0x04, 0x00, 0x01, 0x00, 0x85, 0x02, 0x06, 0x01, 0x04, 0x00, 0x01, 0x00, 0x86, 0x02, 0x06, 0x01, 0x04, 0x00, 0x02, 0x00, 0x01, 0x02, 0x06, 0x01, 0x04, 0x00, 0x02, 0x00, 0x02, 0x02, 0x06, 0x01, 0x04, 0x00, 0x02, 0x00, 0x04, 0x02, 0x06, 0x01, 0x04, 0x00, 0x02, 0x00, 0x80, 0x02, 0x06, 0x01, 0x04, 0x00, 0x02, 0x00, 0x85, 0x02, 0x06, 0x01, 0x04, 0x00, 0x02, 0x00, 0x86, 0x02, 0x06, 0x01, 0x04, 0x00, 0x19, 0x00, 0x41, 0x02, 0x06, 0x01, 0x04, 0x00, 0x19, 0x00, 0x46, 0x02, 0x06, 0x01, 0x04, 0x40, 0x04, 0x00, 0x47, 0x02, 0x06, 0x01, 0x04, 0x40, 0x04, 0x00, 0x48, 0x02, 0x06, 0x41, 0x04, 0x00, 0x00, 0x00, 0x64, 0x02, 0x02, 0x06, 0x00}, MAX_PROTO_BYTES);
    state_1->resp_bytes_sz = 177;
    state_1->search_bytes_seen = true; // We expect client to start state

    state_def *state_2 = state_def_new();
    snprintf(state_2->id, sizeof(state_2->id), "%s", "keepalive");
    state_2->prev = NULL;
    memcpy(state_2->resp_bytes, (char[MAX_PROTO_BYTES]){0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x13, 0x04}, MAX_PROTO_BYTES);
    state_2->resp_bytes_sz = 19;
    // 19 bytes
    state_2->search_bytes_seen = false;
    // Search for server sending open message before allowing to read() resp bytes
    memcpy(state_2->search_bytes[0].bytes, (char[MAX_PROTO_BYTES]){0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x3f, 0x01}, MAX_PROTO_BYTES);
    state_2->search_bytes[0].sz = 19;
    // Search for server sending keepalive message before allowing to read() resp bytes
    memcpy(state_2->search_bytes[1].bytes, (char[MAX_PROTO_BYTES]){0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x13, 0x04}, MAX_PROTO_BYTES);
    state_2->search_bytes[1].sz = 19;

    state_def *state_3 = state_def_new();
    snprintf(state_3->id, sizeof(state_3->id), "%s", "update");
    state_3->prev = NULL;
    // Final state doesn't require waiting for packet from server
    state_3->search_bytes_seen = true;

    state_list[0] = *state_1;
    state_list[1] = *state_2;
    state_list[2] = *state_3;

    if (is_valid_state(state))
    {
        /* Set 0th state index to start state. Intention is that fsm sequence is in
         * ascending order.
         */
        state_list[0].is_current_state = true;
    }
    else
    {
        perror("Specified state id doesn't haven't a match.\n");
    }
}

/* Test if byte array contains subset of byte array.
 * Intented to be used for searching through an array containing network packet bytes for
 * the occurance of interesting bytes in states, that will help determine state transion.
 */
bool contains(const unsigned char *haystack, size_t haystack_sz, const unsigned char *needle, size_t needle_sz)
{
    const char *found = memmem(haystack, haystack_sz, needle, needle_sz);

    if (found && (needle_sz > 0) && (haystack_sz > 0))
    {
        return true;
    }
    else
    {
        return false;
    }
}

/* Test if state search bytes contains expected bytes.
 * Intented to be used for searching through an array containing network packet bytes for
 * the occurance of interesting bytes in states, that will help determine state transion.
 */
bool state_contains(uint state_idx, const unsigned char *haystack, size_t haystack_sz)
{
    bool match = false;
    DEBUG_LOG("[%s:%d:%d] haystack_sz: %d\n", __FUNCTION__, __LINE__, gettid(), haystack_sz);

    for (uint search_idx = 0; search_idx < MAX_SEARCH_BYTES; search_idx++)
    {
        DEBUG_LOG("[%s:%d:%d] haystack_sz: %d, sz: %d\n", __FUNCTION__, __LINE__, gettid(), haystack_sz, state_list[state_idx].search_bytes[search_idx].sz);
        if (state_list[state_idx].search_bytes[search_idx].sz <= 0)
        {
            break;
        }
        match = contains(haystack, haystack_sz, state_list[state_idx].search_bytes[search_idx].bytes, state_list[state_idx].search_bytes[search_idx].sz);

        if (match)
        {
            break;
        }
    }

    return match;
}

/* @Return: true if state matches an entry.
 */
bool set_state_resp_bytes(char *state, char *resp_bytes, size_t buf_size)
{
    for (unsigned int idx = 0; idx < MAX_STATES; idx++)
    {
        DEBUG_LOG("[%s:%d] '%s' buf_size: %d\n", __FUNCTION__, __LINE__, state_list[idx].id, buf_size);

        if (strncmp(state_list[idx].id, state, sizeof(state_list[idx].id)) == 0)
        {
            DEBUG_LOG("[%s:%d] Match '%s' '%s'\n", __FUNCTION__, __LINE__, state, state_list[idx].id);
            memcpy(state_list[idx].resp_bytes, resp_bytes, buf_size);
            state_list[idx].resp_bytes_sz = buf_size;

            return true;
        }
    }
    return false;
}

/* We determine the current fsm state by finding the first element in the
 * state array that has is_current_state == true and the next element in the array has false.
 * @Return: 0 or positive integer to indicate number of bytes returned, negative value indicates error.
 */
ssize_t get_current_state_resp_bytes_and_incr(unsigned char *buf, size_t buf_size)
{
    ssize_t count = -1;

    for (unsigned int state_idx = 0; state_idx < MAX_STATES; state_idx++)
    {
        DEBUG_LOG("[%s:%d] '%s', buf_size: %d\n", __FUNCTION__, __LINE__, state_list[state_idx].id, buf_size);

        int look_ahead_idx = state_idx + 1;
        // Make sure we haven't looked beyond the state array
        if (look_ahead_idx < MAX_STATES)
        {
            if (state_list[state_idx].is_current_state == true)
            {
                // Make sure the next state hasn't been set already
                if (state_list[look_ahead_idx].is_current_state == false)
                {
                    DEBUG_LOG("[%s:%d] '%s'\n", __FUNCTION__, __LINE__, state_list[state_idx].id);

                    if (!is_processed(state_list[state_idx].id))
                    {
                        if (state_list[state_idx].search_bytes_seen)
                        {
                            // Copy current state bytes into buffer
                            count = get_state_resp_bytes(state_list[state_idx].id, buf, buf_size);
                            /* Increment next state by setting flag only if we have
                             * read all the resp bytes from current state.
                             */
                            if (is_processed(state_list[state_idx].id))
                            {
                                state_list[look_ahead_idx].is_current_state = true;
                                // Remaining resp bytes in current state
                            }
                            break;
                        }
                        else // First time read() state bytes, and resp seen flag not set. So we need to waiting for pkts to be write() and matched.
                        {
                            perror("FSM read bytes not processed. Expected peer bytes to have be received.\n");
                        }
                    }
                    else
                    {
                        perror("FSM all processed. Something wrong.\n");
                    }
                }
                // Traverse to next state element
            }
            else
            { // Current state index hasn't had is_current_state flag set. Shouldn't happen
                break;
            }
        }
    }
    return count;
}

/* @returns bool. True if state response bytes are empty. i.e. all read out.
 */
bool is_start_processed()
{
    DEBUG_LOG("[%s:%d]\n", __FUNCTION__, __LINE__);
    return is_processed(state_list[0].id);
}

/* Inform caller that we have sent every fsm state's response bytes, and matched all
 * expected search bytes from peer.
 */
bool is_fsm_end()
{
    if (fsm_completed)
    {
        return true;
    }
    return false;
}

/* Purpose is to determine if the fsm's end state has had
 * is't response byte buffer stored. The buffer would normally
 * have been filled after reading from somewhere like stdin and saved.
 *
 * @returns bool.   True if state response bytes size is non zero.
 */
bool is_end_processed(char *state)
{
    DEBUG_LOG("[%s:%d]\n", __FUNCTION__, __LINE__);
    for (unsigned int idx = 0; idx < MAX_STATES; idx++)
    {
        if (strncmp(state_list[idx].id, state, sizeof(state_list[idx].id)) == 0)
        {
            if (state_list[idx].resp_bytes_sz > 0)
            {
                DEBUG_LOG("[%s:%d] '%s', size: %d\n", __FUNCTION__, __LINE__, state_list[idx].id, state_list[idx].resp_bytes_sz);
                return true;
            };
        }
    }
    return false;
}

/* @returns -1 if unable to determine state, 0 or positive integer for state_list index for current state.
 */
ssize_t
get_current_state_idx()
{
    for (ssize_t idx = 0; idx < MAX_STATES; idx++)
    {
        DEBUG_LOG("[%s:%d]\n", __FUNCTION__, __LINE__);

        int look_ahead_idx = idx + 1;
        // Make sure we haven't looked beyond the state array
        if (look_ahead_idx < MAX_STATES)
        {
            if (state_list[idx].is_current_state == true)
            {
                // Make sure the next state hasn't been set already
                if (state_list[look_ahead_idx].is_current_state == false)
                {
                    DEBUG_LOG("[%s:%d] '%s'\n", __FUNCTION__, __LINE__, state_list[idx].id);
                    // Remaining resp bytes in current state
                    return idx;
                }
                // Traverse to next state element
            }
            else
            { // Current state index hasn't had is_current_state flag set. Shouldn't happen
                DEBUG_LOG("[%s:%d] '%s'\n", __FUNCTION__, __LINE__, state_list[idx].id);
                return -1;
            }
        }
    }
    return -1;
}

/* Caller can send buffer of bytes and this function will set the state's search_bytes_seen flag.
 * This can help to determine transition in fsm.
 */
void set_seen_state_transition(unsigned char *buf, size_t buf_size)
{
    DEBUG_LOG("[%s:%d:%d]\n", __FUNCTION__, __LINE__, gettid());

    ssize_t state_idx;
    if ((state_idx = get_current_state_idx()) < 0)
    {
        _error("Unable to determine state\n");
    }

    DEBUG_LOG("[%s:%d:%d] Flag state for transition based on defined search bytes. state: %s\n", __FUNCTION__, __LINE__, gettid(), state_list[state_idx].id);

    // Only flag the state if the callers buffer contains the state's expected search_bytes buffer
    if (state_contains(state_idx, (const unsigned char *)buf, buf_size))
    {
        DEBUG_LOG("[%s:%d:%d] contains: %d\n", __FUNCTION__, __LINE__, gettid(), state_contains(state_idx, (const unsigned char *)buf, buf_size));
        if (!state_list[state_idx].search_bytes_seen)
        {
            DEBUG_LOG("[%s:%d:%d] Flag state for transition based on defined search bytes. state: %s\n", __FUNCTION__, __LINE__, gettid(), state_list[state_idx].id);

            // Set flag to indicate peer has sent expected bytes for given state
            state_list[state_idx].search_bytes_seen = true;
        }
    }
    else
    {
        DEBUG_LOG("[%s:%d:%d] contains: %d\n", __FUNCTION__, __LINE__, gettid(), state_contains(state_idx, (const unsigned char *)buf, buf_size));
        // We were expecting certain bytes in pkt to indicate fsm transition.
        exit(-1);
        // TODO: Perhaps we should ignore.
    }

    state_idx = get_current_state_idx();
    DEBUG_LOG("[%s:%d:%d] Flag state for transition based on defined search bytes. state: %s\n", __FUNCTION__, __LINE__, gettid(), state_list[state_idx].id);
}

/* @returns bool. True if state response bytes are empty and
 *                search bytes seen from peer.
 */
bool is_processed(char *state)
{
    DEBUG_LOG("[%s:%d]\n", __FUNCTION__, __LINE__);
    for (unsigned int idx = 0; idx < MAX_STATES; idx++)
    {
        if (strncmp(state_list[idx].id, state, sizeof(state_list[idx].id)) == 0)
        {
            if (state_list[idx].resp_bytes_sz <= 0)
            {
                if (state_list[idx].search_bytes_seen)
                {
                    DEBUG_LOG("[%s:%d] '%s'\n", __FUNCTION__, __LINE__, state_list[idx].id);
                    return true;
                }
            }
        }
    }
    return false;
}

/* Read state's response bytes.
 * @Return: 0 or positive integer to indicate number of bytes returned, negative value indicates error.
 *          Will return 0 even if response bytes exist. This can happen if state is dependent on seeing
 *          bytes being sent/write()/send() by peer.
 */
ssize_t get_state_resp_bytes(char *state, unsigned char *buf, size_t buf_size)
{
    ssize_t count = -1;
    ssize_t remaining_resp_bytes = 0;

    for (unsigned int idx = 0; idx < MAX_STATES; idx++)
    {
        DEBUG_LOG("[%s:%d] '%s', buf_size: %d\n", __FUNCTION__, __LINE__, state_list[idx].id, buf_size);

        if (strncmp(state_list[idx].id, state, sizeof(state_list[idx].id)) == 0)
        {
            DEBUG_LOG("[%s:%d] Match '%s' '%s', seen: %d\n", __FUNCTION__, __LINE__, state, state_list[idx].id, state_list[idx].search_bytes_seen);

            // Block sending any state bytes based on
            if (state_list[idx].search_bytes_seen)
            {
                // buf_size must be smaller than state's buf size.
                if (buf_size <= state_list[idx].resp_bytes_sz)
                {
                    // Update callers buffer with resp bytes
                    memcpy(buf, state_list[idx].resp_bytes, buf_size);
                    // Update resp bytes by shifting remaining bytes left. Could have used marker variable to indicate pos.
                    remaining_resp_bytes = state_list[idx].resp_bytes_sz - buf_size;
                    memmove(state_list[idx].resp_bytes, state_list[idx].resp_bytes + buf_size, remaining_resp_bytes);
                    state_list[idx].resp_bytes_sz = remaining_resp_bytes;
                    count = buf_size;

                    DEBUG_LOG("[%s:%d] '%s', buf_size: %d, resp_bytes_sz: %d\n", __FUNCTION__, __LINE__, state_list[idx].id, buf_size, state_list[idx].resp_bytes_sz);
                }
                else if (!is_processed(state))
                {
                    /* Caller is asking for more bytes than available in state.
                     * Copy out all remaining response bytes.
                     */
                    // Update callers buffer with resp bytes
                    buf_size = state_list[idx].resp_bytes_sz;
                    memcpy(buf, state_list[idx].resp_bytes, buf_size);
                    // Update resp bytes by shifting remaining bytes left. Could have used marker variable to indicate pos.
                    // remaining_resp_bytes = state_list[idx].resp_bytes_sz - buf_size;
                    // memmove(state_list[idx].resp_bytes, state_list[idx].resp_bytes + buf_size, buf_size);
                    state_list[idx].resp_bytes_sz = 0;
                    count = buf_size;
                    DEBUG_LOG("[%s:%d] '%s', buf_size: %d, resp_bytes_sz: %d\n", __FUNCTION__, __LINE__, state_list[idx].id, buf_size, state_list[idx].resp_bytes_sz);
                }
                else
                { // All bytes have already been read out.
                    count = 0;
                }
                break;
            }
            break;
        }
    }
    return count;
}

/* Validate if parameter matches a predefined state name */
bool is_valid_state(char *state)
{
    for (unsigned int idx = 0; idx < MAX_STATES; idx++)
    {
        DEBUG_LOG("[%s:%d] '%s'\n", __FUNCTION__, __LINE__, state_list[idx].id);

        if (strncmp(state_list[idx].id, state, sizeof(state_list[idx].id)) == 0)
        {
            DEBUG_LOG("[%s:%d] state: '%s' true\n", __FUNCTION__, __LINE__, state_list[idx].id);
            return true;
        }
    }
    return false;
}

/* Definition: start state has is_current== true and processed==true.
 * End state is_current==false.
 */
bool is_transition_state(char *state)
{
    DEBUG_LOG("[%s:%d] '%s'\n", __FUNCTION__, __LINE__, state);

    if (!is_start_state())
    {
        if (!is_end_state(state))
        {
            for (int idx = 1; idx < MAX_STATES; idx++)
            {
                if (state_list[idx].is_current_state == true)
                {
                    if (is_processed(state_list[idx].id) == false)
                    {
                        return true;
                    }
                    // Continue to next element
                }
                else
                {
                    return false; // Should never reach here unless states incorrectly defined.
                }
            }
        }
    }
    return false;
}

/*  */
bool is_current_state(char *state)
{
    for (unsigned int idx = 0; idx < MAX_STATES; idx++)
    {
        DEBUG_LOG("[%s] '%s'\n", __FUNCTION__, state_list[idx].id);

        if (state_list[idx].is_current_state == true)
        {
            DEBUG_LOG("[%s] Match '%s' '%s' '%d'\n", __FUNCTION__, state, state_list[idx].id, state_list[idx].is_current_state);
            return true;
        }
    }
    return false;
}

/* Check first state element's flag in array and next element's flag not set.
 * If we only have 1 state defined, then we are in both start and end states. Still true.
 */
bool is_start_state()
{
    if (state_list[0].is_current_state == true)
    {
        DEBUG_LOG("[%s:%d] Match '%s' '%d'\n", __FUNCTION__, __LINE__, state_list[0].id, state_list[0].is_current_state);

        if (state_list[1].id == NULL)
        {
            // Only 1 state. Technically we are in both start and end state.
            DEBUG_LOG("[%s:%d]\n", __FUNCTION__, __LINE__);
            return true;
        }
        else
        { // More than 1 state defined
            if (state_list[1].is_current_state == true)
            {
                DEBUG_LOG("[%s:%d]\n", __FUNCTION__, __LINE__);
                // We must have progressed states
                return false;
            }
            else
            {
                DEBUG_LOG("[%s:%d]\n", __FUNCTION__, __LINE__);
                return true;
            }
        }
    }
    return false;
}

/* State id matches callers state name. State flag has been set as current state and hasn't been processed.
 *
 */
bool is_end_state(char *state)
{
    for (unsigned int idx = 0; idx < MAX_STATES; idx++)
    {
        DEBUG_LOG("[%s] '%s'\n", __FUNCTION__, state_list[idx].id);

        if (state_list[idx].is_current_state == true)
        {
            if (strncmp(state_list[idx].id, state, sizeof(state_list[idx].id)) == 0 && is_processed(state_list[idx].id) == false)
            {
                DEBUG_LOG("[%s] Match '%s' '%s' '%d'\n",
                          __FUNCTION__, state, state_list[idx].id, state_list[idx].is_current_state);
                return true;
            }
        }
        else
        {
            // Walking through states and finding one before the end state that hasn't
            // been flagged as current_state means we haven't reached the end yet.
            return false;
        }
    }
    return false;
}