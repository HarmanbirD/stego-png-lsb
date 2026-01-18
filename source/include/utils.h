#ifndef UTILS_H
#define UTILS_H

#include "fsm.h"
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

int   string_to_int(const char *str, int *out, struct fsm_error *err);
int   string_to_uint64(const char *str, uint64_t *out, struct fsm_error *err);
void *safe_malloc(uint32_t size, struct fsm_error *err);

#endif // UTILS_H
