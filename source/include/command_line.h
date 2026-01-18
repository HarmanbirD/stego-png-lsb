#ifndef CLIENT_COMMAND_LINE_H
#define CLIENT_COMMAND_LINE_H

#include "fsm.h"
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

int  parse_arguments(int argc, char *argv[], arguments *args, struct fsm_error *err);
void usage(const char *program_name);
int  handle_arguments(const char *binary_name, arguments *args, struct fsm_error *err);
int  parse_in_port_t(const char *binary_name, const char *str, in_port_t *port, struct fsm_error *err);

#endif // CLIENT_COMMAND_LINE_H
