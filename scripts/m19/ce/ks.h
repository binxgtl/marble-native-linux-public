#ifndef M19_CE_KS_H
#define M19_CE_KS_H

#include "ce.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Keystore2's SP key (getKeyEntry, createOperation, finish) and IKeystoreAuthorization.addAuthToken. */
const struct m19_ce_keystore *m19_ce_ks_ops(void);
void *m19_ce_ks_context(void);

#ifdef __cplusplus
}
#endif

#endif
