#include "fsm.h"

static fsm_state_func fsm_transition(const struct fsm_context *context,
                                     int from_id, int to_id, const struct client_fsm_transition transitions[]);

int fsm_run(struct fsm_context *context, struct fsm_error *err,
            const struct client_fsm_transition transitions[])
{
    int from_id, to_id;

    from_id = FSM_INIT;
    to_id   = FSM_USER_START;

    do {
        fsm_state_func      perform;
        int                 next_id;

        perform             = fsm_transition(context, from_id, to_id, transitions);

        if (perform == NULL)
        {

        }

        from_id             = to_id;
        next_id             = perform(context, err);
        to_id               = next_id;

    } while (to_id != FSM_EXIT);
    return 0;
}


static fsm_state_func fsm_transition(const struct fsm_context *context,
                                     int from_id, int to_id, const struct client_fsm_transition transitions[])
{
    const struct client_fsm_transition *transition;

    transition = &transitions[0];

    while (transition->from_id != FSM_IGNORE)
    {
        if (transition -> from_id == from_id && transition -> to_id == to_id)
        {
            return transition -> perform;
        }

        transition = transitions++;
    }

    return NULL;
}
