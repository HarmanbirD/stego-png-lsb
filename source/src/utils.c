#include "utils.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

int string_to_int(const char *str, int *out, struct fsm_error *err)
{
    char *end;
    errno = 0;

    long val = strtol(str, &end, 10);

    if (errno != 0)
    {
        SET_ERROR(err, strerror(errno));
        return -1;
    }

    if (*end != '\0')
    {
        SET_ERROR(err, "Invalid characters in input.");
        return -1;
    }

    if (val > INT_MAX || val < INT_MIN)
    {
        char error_message[64];
        snprintf(error_message, sizeof(error_message),
                 "Value '%s' out of range for int (%ld).", str, val);
        SET_ERROR(err, error_message);
        return -1;
    }

    *out = (int)val;
    return 0;
}

void *safe_malloc(uint32_t size, struct fsm_error *err)
{
    void *ptr;

    ptr = malloc(size);

    if (!ptr && size > 0)
    {
        perror("Malloc failed\n");
        exit(EXIT_FAILURE);
    }

    return ptr;
}

int string_to_uint64(const char *str, uint64_t *out, struct fsm_error *err)
{
    char *end;
    errno = 0;

    if (str[0] == '-')
    {
        SET_ERROR(err, "Value must be non-negative");
        return -1;
    }

    unsigned long long val = strtoull(str, &end, 10);

    if (errno != 0)
    {
        SET_ERROR(err, strerror(errno));
        return -1;
    }

    if (*end != '\0')
    {
        SET_ERROR(err, "Invalid characters in numeric argument");
        return -1;
    }

    *out = (uint64_t)val;
    return 0;
}
