#ifndef M11_GPR_NATIVE_INTERNAL_H
#define M11_GPR_NATIVE_INTERNAL_H
#include "gpr_native.h"
struct m11_gpr_io {
    void *context;
    int64_t (*open)(void *);
    int64_t (*write)(void *, int, const void *, size_t);
    int64_t (*read)(void *, int, void *, size_t);
    int64_t (*wait)(void *, int, unsigned int);
    int64_t (*close)(void *, int);
    int (*now)(void *, uint64_t *);
    /* 0 healthy observation, 1 DOWN, 2 cancel, negative/error => fail closed. */
    int (*control)(void *);
    int (*record)(void *, const struct m11_gpr_event *);
};
void m11_gpr_worker(const struct m11_gpr_io *, uint32_t, uint64_t, uint64_t);
typedef void (*m11_gpr_child)(int, const struct m11_gpr_session *, uint64_t, uint64_t);
int m11_gpr_supervise(struct m11_gpr_session *, struct m11_gpr_result *, m11_gpr_child);
#endif
