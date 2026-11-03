#define _GNU_SOURCE

#include "endpoint.h"

#include <errno.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef M19_ENDPOINT_LIBRARY
#define M19_ENDPOINT_LIBRARY "libbinder_ndk.so"
#endif

typedef int (*fake_verify_fn)(void);

struct progress_log {
    enum m19_endpoint_stage stages[5];
    unsigned flags[5];
    size_t count;
    int overflow;
};

static int parse_expected_status(const char *text, int *out)
{
    char *end = NULL;
    long value;

    value = strtol(text, &end, 10);
    if (text[0] == '\0' || end == text || *end != '\0' || value < 0 ||
        value > M19_ENDPOINT_STATUS_DESCRIPTOR) {
        return 0;
    }
    *out = (int)value;
    return 1;
}

static void collect_progress(enum m19_endpoint_stage stage,
                             unsigned flags,
                             void *opaque)
{
    struct progress_log *log = opaque;

    if (log->count >= sizeof(log->stages) / sizeof(log->stages[0])) {
        log->overflow = 1;
        return;
    }
    log->stages[log->count] = stage;
    log->flags[log->count] = flags;
    ++log->count;
}

static unsigned expected_flags_for_status(int status)
{
    switch (status) {
    case M19_ENDPOINT_STATUS_OK:
        return M19_ENDPOINT_F_LOADED | M19_ENDPOINT_F_SYMBOLS |
               M19_ENDPOINT_F_FOUND | M19_ENDPOINT_F_DESCRIPTOR |
               M19_ENDPOINT_F_RELEASED;
    case M19_ENDPOINT_STATUS_LOAD:
        return 0;
    case M19_ENDPOINT_STATUS_SYMBOLS:
        return M19_ENDPOINT_F_LOADED;
    case M19_ENDPOINT_STATUS_LOOKUP_NULL:
        return M19_ENDPOINT_F_LOADED | M19_ENDPOINT_F_SYMBOLS;
    case M19_ENDPOINT_STATUS_CLASS:
    case M19_ENDPOINT_STATUS_ASSOCIATE:
    case M19_ENDPOINT_STATUS_DESCRIPTOR:
        return M19_ENDPOINT_F_LOADED | M19_ENDPOINT_F_SYMBOLS |
               M19_ENDPOINT_F_FOUND | M19_ENDPOINT_F_RELEASED;
    default:
        return ~0u;
    }
}

static int expected_errno_for_result(int status)
{
    const char *fault = getenv("M19_ENDPOINT_TEST_FAULT");

    if (fault == NULL) {
        fault = "";
    }
    switch (status) {
    case M19_ENDPOINT_STATUS_LOOKUP_NULL:
        return strcmp(fault, "missingendpoint") == 0 ? ENOENT : 0;
    case M19_ENDPOINT_STATUS_CLASS:
        if (strcmp(fault, "classnull") == 0) {
            return ENOMEM;
        }
        if (strcmp(fault, "getClassnull") == 0) {
            return EBUSY;
        }
        return 0;
    case M19_ENDPOINT_STATUS_ASSOCIATE:
        return strcmp(fault, "associatefalse") == 0 ? EPROTO : 0;
    case M19_ENDPOINT_STATUS_DESCRIPTOR:
        if (strcmp(fault, "getDescnull") == 0) {
            return EFAULT;
        }
        return strcmp(fault, "wrongdesc") == 0 ? EILSEQ : 0;
    default:
        return 0;
    }
}

static size_t expected_progress_count(int status)
{
    switch (status) {
    case M19_ENDPOINT_STATUS_LOAD:
        return 1;
    case M19_ENDPOINT_STATUS_SYMBOLS:
        return 2;
    case M19_ENDPOINT_STATUS_LOOKUP_NULL:
        return 3;
    default:
        return 5;
    }
}

static int check_progress(const struct progress_log *log,
                          const struct m19_endpoint_result *result)
{
    static const enum m19_endpoint_stage stages[] = {
        M19_ENDPOINT_STAGE_LOAD,
        M19_ENDPOINT_STAGE_SYMBOLS,
        M19_ENDPOINT_STAGE_LOOKUP,
        M19_ENDPOINT_STAGE_DESCRIPTOR,
        M19_ENDPOINT_STAGE_RELEASE,
    };
    const size_t expected_count = expected_progress_count(result->status);
    size_t i;

    if (log->overflow || log->count != expected_count) {
        return 0;
    }
    for (i = 0; i < expected_count; ++i) {
        unsigned expected_flags;

        if (log->stages[i] != stages[i]) {
            return 0;
        }
        switch (stages[i]) {
        case M19_ENDPOINT_STAGE_LOAD:
            expected_flags = 0;
            break;
        case M19_ENDPOINT_STAGE_SYMBOLS:
            expected_flags = M19_ENDPOINT_F_LOADED;
            break;
        case M19_ENDPOINT_STAGE_LOOKUP:
            expected_flags = M19_ENDPOINT_F_LOADED |
                             M19_ENDPOINT_F_SYMBOLS;
            break;
        case M19_ENDPOINT_STAGE_DESCRIPTOR:
            expected_flags = M19_ENDPOINT_F_LOADED |
                             M19_ENDPOINT_F_SYMBOLS | M19_ENDPOINT_F_FOUND;
            break;
        case M19_ENDPOINT_STAGE_RELEASE:
            expected_flags = result->flags & ~M19_ENDPOINT_F_RELEASED;
            break;
        default:
            return 0;
        }
        if (log->flags[i] != expected_flags) {
            return 0;
        }
    }
    return 1;
}

static int check_fake_verifier(int expected_status)
{
    void *handle = dlopen(M19_ENDPOINT_LIBRARY, RTLD_NOW | RTLD_LOCAL);
    void *symbol;
    const char *error;
    fake_verify_fn verify = NULL;

    if (handle == NULL) {
        return expected_status == M19_ENDPOINT_STATUS_LOAD;
    }
    (void)dlerror();
    symbol = dlsym(handle, "m19_fake_binder_verify");
    error = dlerror();
    if (error != NULL || symbol == NULL || sizeof(verify) != sizeof(symbol)) {
        return 0;
    }
    memcpy(&verify, &symbol, sizeof(symbol));
    return verify() != 0;
}

int main(int argc, char **argv)
{
    struct m19_endpoint_result result;
    struct progress_log log = {0};
    int expected_status;
    int returned_status;

    if (argc != 2 || !parse_expected_status(argv[1], &expected_status)) {
        fprintf(stderr, "usage: %s expected-status-0-to-6\n", argv[0]);
        return 2;
    }

    returned_status = m19_endpoint_check(collect_progress, &log, &result);
    if (returned_status != expected_status || result.status != expected_status ||
        result.flags != expected_flags_for_status(expected_status) ||
        (expected_status != M19_ENDPOINT_STATUS_LOAD &&
         expected_status != M19_ENDPOINT_STATUS_SYMBOLS &&
         result.detail_errno != expected_errno_for_result(expected_status)) ||
        !check_progress(&log, &result) || !check_fake_verifier(expected_status)) {
        fprintf(stderr,
                "endpoint core mismatch: expected=%d returned=%d status=%d "
                "errno=%d flags=%u progress=%zu\n",
                expected_status, returned_status, result.status,
                result.detail_errno, result.flags, log.count);
        return 1;
    }

    printf("endpoint-core PASS status=%d flags=%u progress=%zu\n",
           result.status, result.flags, log.count);
    return 0;
}
