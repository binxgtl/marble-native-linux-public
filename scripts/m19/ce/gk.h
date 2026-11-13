#ifndef M19_CE_GK_H
#define M19_CE_GK_H

#include "ce.h"

#ifdef __cplusplus
extern "C" {
#endif

struct m19_ce_gk_context {
    const char *library;  /* android.hardware.gatekeeper@1.0.so in the island */
    void *service;        /* the IGatekeeper proxy, held for the process's life */
};

extern const struct m19_ce_gatekeeper m19_ce_gk_ops;

#ifdef __cplusplus
}
#endif

#endif
