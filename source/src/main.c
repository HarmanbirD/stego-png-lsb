#include "command_line.h"
#include "fsm.h"
#include "stego_png.h"
#include <pthread.h>
#include <signal.h>

enum application_states
{
    STATE_PARSE_ARGS = FSM_USER_START,
    STATE_HANDLE_ARGS,
    STATE_LOAD_IMAGE,
    STATE_LOAD_DATA,
    STATE_ENCRYPT_DATA,
    STATE_EMBED_DATA,
    STATE_EXTRACT_DATA,
    STATE_DECRYPT_DATA,
    STATE_OUTPUT,
    STATE_CLEANUP,
    STATE_ERROR,
    STATE_EXIT
};

static int parse_arguments_handler(struct fsm_context *context, struct fsm_error *err);
static int handle_arguments_handler(struct fsm_context *context, struct fsm_error *err);
static int load_image_handler(struct fsm_context *context, struct fsm_error *err);
static int encrypt_data_handler(struct fsm_context *context, struct fsm_error *err);
static int extract_data_handler(struct fsm_context *context, struct fsm_error *err);
static int embed_data_handler(struct fsm_context *context, struct fsm_error *err);
static int output_handler(struct fsm_context *context, struct fsm_error *err);
static int decrypt_data_handler(struct fsm_context *context, struct fsm_error *err);
static int cleanup_handler(struct fsm_context *context, struct fsm_error *err);
static int error_handler(struct fsm_context *context, struct fsm_error *err);

static volatile sig_atomic_t exit_flag = 0;

int main(int argc, char **argv)
{
    struct fsm_error err;
    struct arguments args = {
        .mode = NO_MODE,
    };
    struct fsm_context context = {
        .argc = argc,
        .argv = argv,
        .args = &args,
    };

    static struct client_fsm_transition transitions[] = {
        {FSM_INIT,           STATE_PARSE_ARGS,   parse_arguments_handler },
        {STATE_PARSE_ARGS,   STATE_HANDLE_ARGS,  handle_arguments_handler},
        {STATE_HANDLE_ARGS,  STATE_LOAD_IMAGE,   load_image_handler      },

        {STATE_LOAD_IMAGE,   STATE_ENCRYPT_DATA, encrypt_data_handler    },
        {STATE_LOAD_IMAGE,   STATE_EXTRACT_DATA, extract_data_handler    },

        {STATE_ENCRYPT_DATA, STATE_EMBED_DATA,   embed_data_handler      },
        {STATE_EMBED_DATA,   STATE_OUTPUT,       output_handler          },

        {STATE_EXTRACT_DATA, STATE_DECRYPT_DATA, decrypt_data_handler    },
        {STATE_DECRYPT_DATA, STATE_OUTPUT,       output_handler          },

        {STATE_OUTPUT,       STATE_CLEANUP,      cleanup_handler         },

        {STATE_PARSE_ARGS,   STATE_ERROR,        error_handler           },
        {STATE_HANDLE_ARGS,  STATE_ERROR,        error_handler           },
        {STATE_LOAD_IMAGE,   STATE_ERROR,        error_handler           },
        {STATE_ENCRYPT_DATA, STATE_ERROR,        error_handler           },
        {STATE_EMBED_DATA,   STATE_ERROR,        error_handler           },
        {STATE_EXTRACT_DATA, STATE_ERROR,        error_handler           },
        {STATE_DECRYPT_DATA, STATE_ERROR,        error_handler           },
        {STATE_OUTPUT,       STATE_ERROR,        error_handler           },

        {STATE_ERROR,        STATE_CLEANUP,      cleanup_handler         },
        {STATE_CLEANUP,      STATE_EXIT,         NULL                    },
    };

    fsm_run(&context, &err, transitions);

    return 0;
}

static int parse_arguments_handler(struct fsm_context *context, struct fsm_error *err)
{
    struct fsm_context *ctx;
    ctx = context;
    SET_TRACE(context, "in parse arguments handler", "STATE_PARSE_ARGUMENTS");
    if (parse_arguments(ctx->argc, ctx->argv, ctx->args, err) != 0)
    {
        return STATE_ERROR;
    }

    return STATE_HANDLE_ARGS;
}
static int handle_arguments_handler(struct fsm_context *context, struct fsm_error *err)
{
    struct fsm_context *ctx;
    ctx = context;
    SET_TRACE(context, "in handle arguments", "STATE_HANDLE_ARGUMENTS");
    if (handle_arguments(ctx->argv[0], ctx->args, err) != 0)
    {
        return STATE_ERROR;
    }

    return STATE_LOAD_IMAGE;
}

static int load_image_handler(struct fsm_context *context, struct fsm_error *err)
{
    struct fsm_context *ctx;
    ctx = context;
    SET_TRACE(context, "in convert server_addr", "STATE_CONVERT_ADDRESS");
    if (load_image(ctx->args->png, ctx->args->si, err) != 0)
        return STATE_ERROR;

    if (ctx->args->mode == DECRYPT)
        return STATE_EXTRACT_DATA;

    return STATE_ENCRYPT_DATA;
}

static int encrypt_data_handler(struct fsm_context *context, struct fsm_error *err)
{
    struct fsm_context *ctx;
    ctx = context;
    SET_TRACE(context, "in create socket", "STATE_ENCRYPT_DATA");
    if (encrypt_data(ctx->args->png, ctx->args->key, &ctx->args->payload, &ctx->args->payload_len, err) != 0)
        return STATE_ERROR;

    return STATE_EMBED_DATA;
}

static int extract_data_handler(struct fsm_context *context, struct fsm_error *err)
{
    struct fsm_context *ctx;
    ctx = context;
    SET_TRACE(context, "in bind socket", "STATE_BIND_SOCKET");
    // if (socket_bind(ctx->args->sockfd, &ctx->args->server_addr_struct, err))
    // {
    //     return STATE_ERROR;
    // }

    return STATE_DECRYPT_DATA;
}

static int embed_data_handler(struct fsm_context *context, struct fsm_error *err)
{
    struct fsm_context *ctx;
    ctx = context;
    SET_TRACE(context, "in start listening", "STATE_START_LISTENING");
    // if (start_listening(ctx->args->sockfd, SOMAXCONN, err))
    // {
    //     return STATE_ERROR;
    // }

    return STATE_OUTPUT;
}

static int output_handler(struct fsm_context *context, struct fsm_error *err)
{
    struct fsm_context *ctx;
    ctx = context;
    SET_TRACE(context, "in start listening", "STATE_START_LISTENING");
    // if (start_listening(ctx->args->sockfd, SOMAXCONN, err))
    // {
    //     return STATE_ERROR;
    // }

    return STATE_CLEANUP;
}

static int decrypt_data_handler(struct fsm_context *context, struct fsm_error *err)
{
    struct fsm_context *ctx;
    ctx = context;
    SET_TRACE(context, "in start timer", "STATE_START_TIMER");

    return STATE_OUTPUT;
}

static int cleanup_handler(struct fsm_context *context, struct fsm_error *err)
{
    struct fsm_context *ctx;
    ctx = context;
    SET_TRACE(context, "in cleanup handler", "STATE_CLEANUP");

    return FSM_EXIT;
}

static int error_handler(struct fsm_context *context, struct fsm_error *err)
{
    fprintf(stderr, "ERROR %s\nIn file %s in function %s on line %d\n", err->err_msg, err->file_name,
            err->function_name, err->error_line);

    return STATE_CLEANUP;
}
