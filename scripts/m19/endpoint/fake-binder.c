#define _GNU_SOURCE

#include <signal.h>
#include <stdbool.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

#if !defined(M19_FAKE_OMIT_AServiceManager_checkService)
static const char k_instance[] =
    "android.system.keystore2.IKeystoreService/default";
static const char k_wrong_remote_descriptor[] =
    "android.system.keystore2.IKeystoreService.Wrong";
#endif
static const char k_descriptor[] =
    "android.system.keystore2.IKeystoreService";

struct AIBinder {
    const char *descriptor;
};

struct AIBinder_Class {
    char descriptor[129];
    AIBinder_Class_onCreate on_create;
    AIBinder_Class_onDestroy on_destroy;
    AIBinder_Class_onTransact on_transact;
};

struct AParcel {
    int unused;
};

static AIBinder s_binder = {k_descriptor};
static AIBinder_Class s_class;
static AIBinder_Class *s_associated_class;
static unsigned s_state;
static unsigned s_check_service_calls;
static unsigned s_class_define_calls;
static unsigned s_associate_calls;
static unsigned s_get_class_calls;
static unsigned s_get_descriptor_calls;
static unsigned s_dec_strong_calls;
static unsigned s_mark_sensitive_calls;
static int s_protocol_ok = 1;
#if !defined(M19_FAKE_OMIT_AIBinder_Class_getDescriptor)
static char s_long_descriptor[130];
#endif

static const char *fault(void)
{
    const char *value = getenv("M19_ENDPOINT_TEST_FAULT");
    return value == NULL ? "" : value;
}

static int is_fault(const char *name)
{
    return strcmp(fault(), name) == 0;
}

static void block_if_requested(const char *api_name)
{
    int should_block =
        (strcmp(api_name, "checkService") == 0 && is_fault("blocklookup")) ||
        (strcmp(api_name, "associateClass") == 0 && is_fault("blockassoc")) ||
        (strcmp(api_name, "decStrong") == 0 && is_fault("blockrelease"));
    if (should_block) {
        /* A supervisor test can observe and terminate a worker stopped here. */
        (void)raise(SIGSTOP);
        for (;;) {
            pause();
        }
    }
}

__attribute__((constructor)) static void fake_library_constructor(void)
{
#ifdef M19_FAKE_SHADOW
    /* Offline-only decoy: proves a basename lookup executes redirected code. */
    _exit(90);
#endif
    if (is_fault("block-loadctor")) {
        (void)raise(SIGSTOP);
        for (;;) {
            pause();
        }
    }
}

static void record_order(unsigned expected_state)
{
    if (s_state != expected_state) {
        s_protocol_ok = 0;
    }
}

#if !defined(M19_FAKE_OMIT_AParcel_markSensitive)
void AParcel_markSensitive(const AParcel *parcel)
{
    (void)parcel;
    ++s_mark_sensitive_calls;
    s_protocol_ok = 0;
}
#endif

#if !defined(M19_FAKE_OMIT_AServiceManager_checkService)
AIBinder *AServiceManager_checkService(const char *instance)
{
    block_if_requested("checkService");
    record_order(0);
    ++s_state;
    ++s_check_service_calls;
    if (instance == NULL || strcmp(instance, k_instance) != 0) {
        s_protocol_ok = 0;
    }
    if (is_fault("missingendpoint")) {
        errno = ENOENT;
        return NULL;
    }
    s_binder.descriptor = is_fault("wrongremote")
                              ? k_wrong_remote_descriptor
                              : k_descriptor;
    return &s_binder;
}
#endif

#if !defined(M19_FAKE_OMIT_AIBinder_Class_define)
AIBinder_Class *AIBinder_Class_define(const char *descriptor,
                                     AIBinder_Class_onCreate on_create,
                                     AIBinder_Class_onDestroy on_destroy,
                                     AIBinder_Class_onTransact on_transact)
{
    size_t length;

    block_if_requested("classDefine");
    record_order(1);
    ++s_state;
    ++s_class_define_calls;
    if (descriptor == NULL || strcmp(descriptor, k_descriptor) != 0 ||
        on_create == NULL || on_destroy == NULL || on_transact == NULL) {
        s_protocol_ok = 0;
    }

    memset(&s_class, 0, sizeof(s_class));
    if (descriptor != NULL) {
        length = strlen(descriptor);
        if (length >= sizeof(s_class.descriptor)) {
            length = sizeof(s_class.descriptor) - 1;
            s_protocol_ok = 0;
        }
        memcpy(s_class.descriptor, descriptor, length);
        s_class.descriptor[length] = '\0';
    }
    s_class.on_create = on_create;
    s_class.on_destroy = on_destroy;
    s_class.on_transact = on_transact;

    if (is_fault("unexpectedcallback")) {
        (void)on_create(NULL);
        _exit(124);
    }
    if (is_fault("classnull")) {
        errno = ENOMEM;
        return NULL;
    }
    return &s_class;
}
#endif

#if !defined(M19_FAKE_OMIT_AIBinder_associateClass)
bool AIBinder_associateClass(AIBinder *binder, const AIBinder_Class *clazz)
{
    block_if_requested("associateClass");
    record_order(2);
    ++s_state;
    ++s_associate_calls;
    if (binder != &s_binder || clazz != &s_class ||
        binder->descriptor == NULL) {
        s_protocol_ok = 0;
        return false;
    }
    if (strcmp(binder->descriptor, clazz->descriptor) != 0) {
        return false;
    }
    if (is_fault("associatefalse")) {
        errno = EPROTO;
        return false;
    }
    s_associated_class = (AIBinder_Class *)clazz;
    return true;
}
#endif

#if !defined(M19_FAKE_OMIT_AIBinder_getClass)
const AIBinder_Class *AIBinder_getClass(AIBinder *binder)
{
    block_if_requested("getClass");
    record_order(3);
    ++s_state;
    ++s_get_class_calls;
    if (binder != &s_binder) {
        s_protocol_ok = 0;
        return NULL;
    }
    if (is_fault("getClassnull")) {
        errno = EBUSY;
        return NULL;
    }
    return s_associated_class;
}
#endif

#if !defined(M19_FAKE_OMIT_AIBinder_Class_getDescriptor)
const char *AIBinder_Class_getDescriptor(const AIBinder_Class *clazz)
{
    size_t i;

    block_if_requested("getDescriptor");
    record_order(4);
    ++s_state;
    ++s_get_descriptor_calls;
    if (clazz != &s_class) {
        s_protocol_ok = 0;
        return NULL;
    }
    if (is_fault("getDescnull")) {
        errno = EFAULT;
        return NULL;
    }
    if (is_fault("wrongdesc")) {
        errno = EILSEQ;
        return "android.system.keystore2.IKeystoreService.Wrong";
    }
    if (is_fault("longdesc")) {
        for (i = 0; i < sizeof(s_long_descriptor) - 1; ++i) {
            s_long_descriptor[i] = 'x';
        }
        s_long_descriptor[sizeof(s_long_descriptor) - 1] = '\0';
        return s_long_descriptor;
    }
    return clazz->descriptor;
}
#endif

#if !defined(M19_FAKE_OMIT_AIBinder_decStrong)
void AIBinder_decStrong(AIBinder *binder)
{
    block_if_requested("decStrong");
    if (binder != &s_binder || s_state < 1 || s_state > 5) {
        s_protocol_ok = 0;
    }
    ++s_dec_strong_calls;
    s_state = 6;
    errno = EDOM;
}
#endif

int m19_fake_binder_verify(void)
{
#if defined(M19_FAKE_OMIT_AParcel_markSensitive) || \
    defined(M19_FAKE_OMIT_AServiceManager_checkService) || \
    defined(M19_FAKE_OMIT_AIBinder_Class_define) || \
    defined(M19_FAKE_OMIT_AIBinder_associateClass) || \
    defined(M19_FAKE_OMIT_AIBinder_getClass) || \
    defined(M19_FAKE_OMIT_AIBinder_Class_getDescriptor) || \
    defined(M19_FAKE_OMIT_AIBinder_decStrong)
    return s_protocol_ok && s_check_service_calls == 0 &&
           s_class_define_calls == 0 && s_associate_calls == 0 &&
           s_get_class_calls == 0 && s_get_descriptor_calls == 0 &&
           s_dec_strong_calls == 0 && s_mark_sensitive_calls == 0;
#else
    unsigned expected_define = 0;
    unsigned expected_associate = 0;
    unsigned expected_get_class = 0;
    unsigned expected_get_descriptor = 0;
    unsigned expected_dec_strong = 0;
    unsigned expected_lookup = 0;
    int found = 0;

    expected_lookup = 1;
    found = !is_fault("missingendpoint");
    if (found) {
        expected_dec_strong = 1;
        expected_define = 1;
        expected_associate = is_fault("classnull") ? 0u : 1u;
        expected_get_class =
            (is_fault("classnull") || is_fault("associatefalse") ||
             is_fault("wrongremote"))
                ? 0u
                : 1u;
        expected_get_descriptor =
            (is_fault("classnull") || is_fault("associatefalse") ||
             is_fault("wrongremote") || is_fault("getClassnull"))
                ? 0u
                : 1u;
    }

    if (s_check_service_calls != expected_lookup ||
        s_class_define_calls != expected_define ||
        s_associate_calls != expected_associate ||
        s_get_class_calls != expected_get_class ||
        s_get_descriptor_calls != expected_get_descriptor ||
        s_dec_strong_calls != expected_dec_strong ||
        s_mark_sensitive_calls != 0 || !s_protocol_ok) {
        return 0;
    }
    if (found && s_state != 6) {
        return 0;
    }
    if (!found && s_state != 1) {
        return 0;
    }
    return 1;
#endif
}
