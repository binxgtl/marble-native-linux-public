#ifndef M19_CE_CRYPTO_H
#define M19_CE_CRYPTO_H

#include "ce.h"

#ifdef __cplusplus
extern "C" {
#endif

/* NULL unless every symbol resolves. The handle stays open for the process's life. */
const struct m19_ce_crypto *m19_ce_crypto_open(const char *path);

#ifdef __cplusplus
}
#endif

#endif
