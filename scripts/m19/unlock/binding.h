#ifndef M19_BINDING_H
#define M19_BINDING_H

#include "core.h"
#include "probe.h"

const struct m19_keystore_ops *m19_keystore2_ops(void);
void *m19_keystore2_context(void);
void m19_keystore2_progress(m19_probe_progress callback, void *context);
enum m19_upgrade_fact m19_keystore2_upgrade(void);
int m19_keystore2_upgrade_observed(void);

#endif
