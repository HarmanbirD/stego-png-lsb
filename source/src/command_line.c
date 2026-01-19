#include "command_line.h"
#include "fsm.h"
#include "utils.h"

int parse_arguments(int argc, char *argv[], arguments *args, struct fsm_error *err)
{
    int opt;
    int f_flag, k_flag, p_flag, d_flag, e_flag;

    opterr = 0;
    f_flag = 0;
    k_flag = 0;
    p_flag = 0;
    d_flag = 0;
    e_flag = 0;

    static struct option long_opts[] = {
        {"png",     required_argument, 0, 'p'},
        {"file",    required_argument, 0, 'f'},
        {"key",     required_argument, 0, 'k'},
        {"encrypt", no_argument,       0, 'e'},
        {"decrypt", no_argument,       0, 'd'},
        {"help",    no_argument,       0, 'h'},
        {0,         0,                 0, 0  },
    };

    while ((opt = getopt_long(argc, argv, "p:f:k:e:dh", long_opts, NULL)) != -1)
    {
        switch (opt)
        {
            case 'f':
            {
                if (f_flag)
                {
                    usage(argv[0]);

                    SET_ERROR(err, "option '-f' can only be passed in once.");

                    return -1;
                }

                f_flag++;
                args->message = optarg;
                break;
            }
            case 'k':
            {
                if (k_flag)
                {
                    usage(argv[0]);

                    SET_ERROR(err, "option '-k' can only be passed in once.");

                    return -1;
                }

                k_flag++;
                args->key = optarg;
                break;
            }
            case 'p':
            {
                if (p_flag)
                {
                    usage(argv[0]);

                    SET_ERROR(err, "option '-p' can only be passed in once.");

                    return -1;
                }

                p_flag++;
                args->png = optarg;
                break;
            }
            case 'e':
            {
                if (e_flag)
                {
                    usage(argv[0]);

                    SET_ERROR(err, "option '-e' can only be passed in once.");

                    return -1;
                }

                if (d_flag)
                {
                    usage(argv[0]);

                    SET_ERROR(err, "option '-e' or option '-d' can be passed in, not both.");

                    return -1;
                }

                e_flag++;
                args->mode = ENCRYPT;
                break;
            }
            case 'd':
            {
                if (d_flag)
                {
                    usage(argv[0]);

                    SET_ERROR(err, "option '-d' can only be passed in once.");

                    return -1;
                }

                if (e_flag)
                {
                    usage(argv[0]);

                    SET_ERROR(err, "option '-e' or option '-d' can be passed in, not both.");

                    return -1;
                }

                d_flag++;
                args->mode = DECRYPT;
                break;
            }
            case 'h':
            {
                usage(argv[0]);

                SET_ERROR(err, "user called for help");

                return -1;
            }
            case '?':
            {
                char message[24];

                snprintf(message, sizeof(message), "Unknown option '-%c'.", optopt);
                usage(argv[0]);
                SET_ERROR(err, message);

                return -1;
            }
            default:
            {
                usage(argv[0]);
            }
        }
    }

    if (optind < argc)
    {
        usage(argv[0]);

        SET_ERROR(err, "Too many options.");

        return -1;
    }

    return 0;
}

void usage(const char *program_name)
{
    fprintf(stderr,
            "Usage: %s [OPTIONS]\n\n"
            "Required options:\n"
            "  -s, --server <addr>       Server IP address or hostname (required)\n"
            "  -p, --port <num>          Server listen port (required)\n"
            "  -H, --hash <hash>         Hashed password to crack (required)\n\n"
            "Optional options:\n"
            "  -w, --work-size <num>     Number of passwords assigned per node request\n"
            "                             (default: 1000)\n"
            "  -c, --checkpoint <num>    Number of attempts before a node sends a checkpoint\n"
            "                             (default: work-size / 4)\n"
            "  -t, --timeout <num>       Seconds to wait for a checkpoint from a client\n"
            "                             (default: 600)\n"
            "  -h, --help                Display this help message and exit\n\n"
            "Examples:\n"
            "  %s --server 192.168.1.10 --port 5000 --hash $6$... --work-size 1000\n"
            "  %s -s example.com -p 5000 -H <hash> -c 500 -t 300\n\n",
            program_name, program_name, program_name);

    fputs("Notes:\n", stderr);
    fputs("  • Long and short forms may be used interchangeably (e.g. --port or -p).\n", stderr);
    fputs("  • If work-size is omitted it defaults to 1000.\n", stderr);
    fputs("  • If checkpoint is omitted it defaults to work-size / 4.\n", stderr);
    fputs("  • The program will validate numeric ranges (e.g. port must fit in uint16).\n", stderr);
}

int handle_arguments(const char *binary_name, arguments *args, struct fsm_error *err)
{
    if (args->png == NULL)
    {
        SET_ERROR(err, "User has to pass in a valid PNG.");
        usage(binary_name);

        return -1;
    }

    if (args->message == NULL)
    {
        if (args->mode != DECRYPT)
        {
            SET_ERROR(err, "Have to pass in a readable file for the message.");
            usage(binary_name);

            return -1;
        }
    }

    if (args->key == NULL)
    {
        SET_ERROR(err, "Have to pass in the key to encrypt the message");
        usage(binary_name);

        return -1;
    }

    if (args->mode == NO_MODE)
    {
        args->mode = ENCRYPT;
    }

    return 0;
}
