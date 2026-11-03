#define _GNU_SOURCE

#include "endpoint.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>

#if defined(__ANDROID__)
#include <android/binder_ibinder.h>
#else
/* Host-test declarations mirror the public Binder NDK callback ABI. */
typedef struct AIBinder AIBinder;
typedef struct AIBinder_Class AIBinder_Class;
typedef struct AParcel AParcel;
typedef int32_t binder_status_t;
typedef uint32_t transaction_code_t;
typedef void *(*AIBinder_Class_onCreate)(void *args);
typedef void (*AIBinder_Class_onDestroy)(void *user_data);
typedef binder_status_t (*AIBinder_Class_onTransact)(AIBinder *binder,
                                                      transaction_code_t code,
                                                      const AParcel *in,
                                                      AParcel *out);
#endif

#ifndef M19_ENDPOINT_LIBRARY
#define M19_ENDPOINT_LIBRARY "libbinder_ndk.so"
#endif

static const char k_instance[] =
    "android.system.keystore2.IKeystoreService/default";
static const char k_descriptor[] =
    "android.system.keystore2.IKeystoreService";
static AIBinder_Class *s_service_class;

typedef AIBinder *(*check_service_fn)(const char *instance);
typedef AIBinder_Class *(*class_define_fn)(
    const char *descriptor,
    AIBinder_Class_onCreate on_create,
    AIBinder_Class_onDestroy on_destroy,
    AIBinder_Class_onTransact on_transact);
typedef bool (*associate_class_fn)(AIBinder *binder,
                                  const AIBinder_Class *clazz);
typedef const AIBinder_Class *(*get_class_fn)(AIBinder *binder);
typedef const char *(*get_descriptor_fn)(const AIBinder_Class *clazz);
typedef void (*dec_strong_fn)(AIBinder *binder);

struct m19_endpoint_api {
    check_service_fn check_service;
    class_define_fn class_define;
    associate_class_fn associate_class;
    get_class_fn get_class;
    get_descriptor_fn get_descriptor;
    dec_strong_fn dec_strong;
};

/* Binder must never dispatch business calls through this endpoint-only class. */
static void *reject_on_create(void *args)
{
    (void)args;
    _exit(125);
}

static void reject_on_destroy(void *user_data)
{
    (void)user_data;
    _exit(125);
}

static binder_status_t reject_on_transact(AIBinder *binder,
                                           transaction_code_t code,
                                           const AParcel *in,
                                           AParcel *out)
{
    (void)binder;
    (void)code;
    (void)in;
    (void)out;
    _exit(125);
}

static void emit_progress(m19_endpoint_progress progress,
                          enum m19_endpoint_stage stage,
                          unsigned flags,
                          void *opaque)
{
    if (progress != NULL) {
        progress(stage, flags, opaque);
    }
}

/* POSIX dlsym returns an object pointer; copy its representation into the
 * function-pointer slot rather than relying on an ISO C pointer cast. */
static int resolve_symbol(void *handle,
                          const char *name,
                          void *destination,
                          size_t destination_size,
                          int *error_number)
{
    void *address;
    const char *error;
    int observed_errno;

    (void)dlerror();
    errno = 0;
    address = dlsym(handle, name);
    observed_errno = errno;
    error = dlerror();
    if (error != NULL || address == NULL ||
        destination_size != sizeof(address)) {
        *error_number = observed_errno;
        return 0;
    }
    memcpy(destination, &address, sizeof(address));
    return 1;
}

static int descriptor_matches(const char *descriptor)
{
    size_t length = 0;

    if (descriptor == NULL) {
        return 0;
    }
    while (length <= 128 && descriptor[length] != '\0') {
        ++length;
    }
    if (length > 128 || length != sizeof(k_descriptor) - 1) {
        return 0;
    }
    return memcmp(descriptor, k_descriptor, sizeof(k_descriptor)) == 0;
}

int m19_endpoint_check(m19_endpoint_progress progress,
                       void *opaque,
                       struct m19_endpoint_result *result)
{
    struct m19_endpoint_api api = {0};
    void *handle;
    void *mark_sensitive = NULL;
    AIBinder *binder = NULL;
    const AIBinder_Class *associated_class;
    const AIBinder_Class *actual_class;
    const char *actual_descriptor;
    int status = M19_ENDPOINT_STATUS_OK;
    int captured_errno = 0;

    result->status = M19_ENDPOINT_STATUS_OK;
    result->detail_errno = 0;
    result->flags = 0;

    emit_progress(progress, M19_ENDPOINT_STAGE_LOAD, result->flags, opaque);
    errno = 0;
    handle = dlopen(M19_ENDPOINT_LIBRARY, RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        captured_errno = errno;
        status = M19_ENDPOINT_STATUS_LOAD;
        goto finish_without_binder;
    }
    result->flags |= M19_ENDPOINT_F_LOADED;

    emit_progress(progress, M19_ENDPOINT_STAGE_SYMBOLS, result->flags, opaque);
    /* This symbol is a resolution checkpoint only and is never invoked. */
    if (!resolve_symbol(handle, "AParcel_markSensitive", &mark_sensitive,
                        sizeof(mark_sensitive), &captured_errno) ||
        !resolve_symbol(handle, "AServiceManager_checkService",
                        &api.check_service, sizeof(api.check_service),
                        &captured_errno) ||
        !resolve_symbol(handle, "AIBinder_Class_define", &api.class_define,
                        sizeof(api.class_define), &captured_errno) ||
        !resolve_symbol(handle, "AIBinder_associateClass",
                        &api.associate_class, sizeof(api.associate_class),
                        &captured_errno) ||
        !resolve_symbol(handle, "AIBinder_getClass", &api.get_class,
                        sizeof(api.get_class), &captured_errno) ||
        !resolve_symbol(handle, "AIBinder_Class_getDescriptor",
                        &api.get_descriptor, sizeof(api.get_descriptor),
                        &captured_errno) ||
        !resolve_symbol(handle, "AIBinder_decStrong", &api.dec_strong,
                        sizeof(api.dec_strong), &captured_errno)) {
        status = M19_ENDPOINT_STATUS_SYMBOLS;
        goto finish_without_binder;
    }
    (void)mark_sensitive;
    result->flags |= M19_ENDPOINT_F_SYMBOLS;

    emit_progress(progress, M19_ENDPOINT_STAGE_LOOKUP, result->flags, opaque);
    errno = 0;
    binder = api.check_service(k_instance);
    if (binder == NULL) {
        captured_errno = errno;
        status = M19_ENDPOINT_STATUS_LOOKUP_NULL;
        goto finish_without_binder;
    }
    result->flags |= M19_ENDPOINT_F_FOUND;

    emit_progress(progress, M19_ENDPOINT_STAGE_DESCRIPTOR, result->flags,
                   opaque);
    if (s_service_class == NULL) {
        errno = 0;
        s_service_class = api.class_define(k_descriptor, reject_on_create,
                                            reject_on_destroy,
                                            reject_on_transact);
        if (s_service_class == NULL) {
            captured_errno = errno;
            status = M19_ENDPOINT_STATUS_CLASS;
            goto release_binder;
        }
    }

    associated_class = s_service_class;
    errno = 0;
    if (!api.associate_class(binder, associated_class)) {
        captured_errno = errno;
        status = M19_ENDPOINT_STATUS_ASSOCIATE;
        goto release_binder;
    }

    errno = 0;
    actual_class = api.get_class(binder);
    if (actual_class == NULL) {
        captured_errno = errno;
        status = M19_ENDPOINT_STATUS_CLASS;
        goto release_binder;
    }

    errno = 0;
    actual_descriptor = api.get_descriptor(actual_class);
    if (actual_descriptor == NULL) {
        captured_errno = errno;
        status = M19_ENDPOINT_STATUS_DESCRIPTOR;
        goto release_binder;
    }
    if (!descriptor_matches(actual_descriptor)) {
        captured_errno = errno;
        status = M19_ENDPOINT_STATUS_DESCRIPTOR;
        goto release_binder;
    }
    result->flags |= M19_ENDPOINT_F_DESCRIPTOR;

release_binder:
    result->status = status;
    result->detail_errno = captured_errno;
    emit_progress(progress, M19_ENDPOINT_STAGE_RELEASE, result->flags,
                   opaque);
    api.dec_strong(binder);
    result->flags |= M19_ENDPOINT_F_RELEASED;
    return status;

finish_without_binder:
    result->status = status;
    result->detail_errno = captured_errno;
    return status;
}
