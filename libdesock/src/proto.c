/* Template implementaiton for a statefull protocol. Use to assist with fuzzing.
 */
#define __USE_GNU
#define GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/un.h>
#include <unistd.h>
#include "proto.h"
#include "desock.h"


state_def state_open = {
    .id = {"OPEN"},
    .is_processed = false,
    .prev = NULL, // 53764 = 1234, 45824 = 179
    .search_bytes = {0xff},
    .resp_bytes = {0x41, 0x42, 0x43, 0x44}
};

state_def state_update = {
    .id = {"UPDATE"},
    .is_processed = false,
    .prev = NULL, // 53764 = 1234, 45824 = 179
    .search_bytes = {0xff},
    .resp_bytes = {0x45, 0x46, 0x47}
};

/*  */
state_def state_list[MAX_STATES];

/* Configured via environment variable DESOCK_STATE.
 * e.g. "OPEN\0"
 */
char desock_state[MAX_STATE_ID];

/* Use this initializer/constructor for state_def types.
 */
state_def *state_def_new() {
    state_def *my_state = malloc(sizeof(state_def));
    memset(my_state->id, '\0', sizeof(MAX_STATE_ID));
    my_state->is_current_state = false;
    my_state->is_processed = false;
    return my_state;
}

/* Initialize fsm structs into data structure that will help
   us navigate between states.
 */
void init_state_list(char *state) {
    /* Define our state objects before assigning to state_list */
    state_def *state_1 = state_def_new();
    strncpy(state_1->id, "state1", sizeof(state_1->id));
    state_1->prev = NULL;
    memcpy(state_1->resp_bytes, (char [MAX_PROTO_BYTES]){'s','t','a','t','e','1','\n'}, MAX_PROTO_BYTES);

    state_def *state_2 = state_def_new();
    strncpy(state_2->id, "state2", sizeof(state_2->id));
    state_2->prev = NULL;
    memcpy(state_2->resp_bytes, (char [MAX_PROTO_BYTES]){'s','t','a','t','e','2','\n'}, MAX_PROTO_BYTES);

    state_def *state_3 = state_def_new();
    strncpy(state_3->id, "state3", sizeof(state_3->id));
    state_3->prev = NULL;
    memcpy(state_3->resp_bytes, (char [MAX_PROTO_BYTES]){'s','t','a','t','e','3','\n'}, MAX_PROTO_BYTES);

    state_list[0] = *state_1;
    state_list[1] = *state_2;
    state_list[2] = *state_3;

    if (is_valid_state(state)) {
        /* Set 0th state index to start state. Intention is that fsm sequence is in 
         * ascending order.
         */
        state_list[0].is_current_state = true;
    }
    else {
        perror("Specified state id doesn't haven't a match.\n");
    }
}

/* @Return: true if state matches an entry.
 * TODO: add size parameter.
 */
bool set_state_resp_bytes(char *state, char *resp_bytes) {
    for (unsigned int idx = 0; idx < MAX_STATES; idx++) {
        DEBUG_LOG ("[%s] '%s'\n", __FUNCTION__, state_list[idx].id);
        
        if (strncmp(state_list[idx].id, state, sizeof(state_list[idx].id)) == 0) {
            DEBUG_LOG ("[%s] Match '%s' '%s'\n", __FUNCTION__, state, state_list[idx].id);
            memcpy(state_list[idx].resp_bytes, resp_bytes, MAX_PROTO_BYTES);

            return true;
        }
    }
    return false;
}

/* We determine the current fsm state by finding the first element in the 
 * state array that has is_current_state == true and the next element in the array has false.
 * @Return: true if state matches an entry.
 */
bool get_current_state_resp_bytes_and_incr(unsigned char *buf, size_t buf_size) {
    for (unsigned int idx = 0; idx < MAX_STATES; idx++) {
        DEBUG_LOG ("[%s] '%s'\n", __FUNCTION__, state_list[idx].id);

        int look_ahead_idx = idx + 1;
        // Make sure we haven't looked beyond the state array
        if (look_ahead_idx < MAX_STATES) {
            if (state_list[idx].is_current_state == true) {
                // Make sure the next state hasn't been set already
                if (state_list[look_ahead_idx].is_current_state == false) {
                    DEBUG_LOG ("[%s:%d] '%s'\n", __FUNCTION__, __LINE__, state_list[idx].id);
                    // Copy current state bytes into buffer
                    get_state_resp_bytes(state_list[idx].id, buf, buf_size);
                    // Increment next state by setting flag
                    state_list[look_ahead_idx].is_current_state = true;
        
                    return true;
                }
                // Traverse to next state element
            }
            else { // Current state index hasn't had is_current_state flag set. Shouldn't happen
                return false;
            }
        }
    }
    return false;
}

/* 
 * @Return: true if state matches an entry.
 */
bool get_state_resp_bytes(char *state, unsigned char *buf, size_t buf_size) {
    for (unsigned int idx = 0; idx < MAX_STATES; idx++) {
        DEBUG_LOG ("[%s:%d] buf_size:%d, '%s'\n", __FUNCTION__, __LINE__, buf_size, state_list[idx].id);
        
        if (strncmp(state_list[idx].id, state, sizeof(state_list[idx].id)) == 0) {
            DEBUG_LOG ("[%s:%d] Match '%s' '%s' '%s'\n", __FUNCTION__, __LINE__, state, state_list[idx].id, state_list[idx].resp_bytes);
            memcpy(buf, state_list[idx].resp_bytes, buf_size);
            // Set a flag that indicates we have read the resp bytes. This indicates callers
            // intent to send the fsm bytes and will not do so again.
            state_list[idx].is_processed = true;

            return true;
        }
    }
    return false;
}

/* Validate if parameter matches a predefined state name */
bool is_valid_state(char *state) {
    for (unsigned int idx = 0; idx < MAX_STATES; idx++) {
        DEBUG_LOG ("[%s] '%s'\n", __FUNCTION__, state_list[idx].id);

        if (strncmp(state_list[idx].id, state, sizeof(state_list[idx].id)) == 0) {
            DEBUG_LOG ("[%s] Match '%s' '%s'\n", __FUNCTION__, state, state_list[idx].id);
            return true;
        }
    }
    return false;
}

/* Definition: start state has is_current== true and processed==true. 
 * End state is_current==false.
 */
bool is_transition_state(char *state) {
    if (!is_start_state()) {
        if (!is_end_state(state)) {
            for (int idx = 1; idx < MAX_STATES; idx++) {
                if (state_list[idx].is_current_state == true) { 
                    if (state_list[idx].is_processed == false) {
                        return true;
                    }
                    // Continue to next element
                }
                else {
                    return false; // Should never reach here unless states incorrectly defined.
                }
            }
        }
    }
    return false;
}

/*  */
bool is_current_state(char *state) {
    for (unsigned int idx = 0; idx < MAX_STATES; idx++) {
        DEBUG_LOG ("[%s] '%s'\n", __FUNCTION__, state_list[idx].id);

        if (state_list[idx].is_current_state == true) {
            DEBUG_LOG ("[%s] Match '%s' '%s' '%d'\n", __FUNCTION__, state, state_list[idx].id, state_list[idx].is_current_state);
            return true;
        }
    }
    return false;
}

/* Check first state element's flag in array and next element's flag not set.
 * If we only have 1 state defined, then we are in both start and end states. Still true.
 */
bool is_start_state() {
    if (state_list[0].is_current_state == true) {
        DEBUG_LOG ("[%s:%d] Match '%s' '%d'\n", __FUNCTION__, __LINE__, state_list[0].id, state_list[0].is_current_state);

        if (state_list[1].id == NULL) {
            // Only 1 state. Technically we are in both start and end state.
            DEBUG_LOG ("[%s:%d]\n", __FUNCTION__, __LINE__);
            return true;
        }
        else { // More than 1 state defined
            if (state_list[1].is_current_state == true) {
                DEBUG_LOG ("[%s:%d]\n", __FUNCTION__, __LINE__);
                // We must have progressed states
                return false;
            }
            else {
                DEBUG_LOG ("[%s:%d]\n", __FUNCTION__, __LINE__);
                return true;
            }
        }
    }
    return false;
}

/* State id matches callers state name. State flag has been set as current state and hasn't been processed.   
 *
 */
bool is_end_state(char *state) {
    for (unsigned int idx = 0; idx < MAX_STATES; idx++) {
        DEBUG_LOG ("[%s] '%s'\n", __FUNCTION__, state_list[idx].id);

        if (state_list[idx].is_current_state == true) {
            if (strncmp(state_list[idx].id, state, sizeof(state_list[idx].id)) == 0 
                    && state_list[idx].is_processed == false) {
                DEBUG_LOG ("[%s] Match '%s' '%s' '%d'\n", 
                    __FUNCTION__, state, state_list[idx].id, state_list[idx].is_current_state);
                return true;
            }
        }
        else {
            // Walking through states and finding one before the end state that hasn't
            // been flagged as current_state means we haven't reached the end yet.
            return false;
        }
    }
    return false;
}

/* Tried execute on load. Not working.
void __attribute__((constructor)) init_state_list();
 */