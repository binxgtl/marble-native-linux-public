#ifndef M19_DM_H
#define M19_DM_H

#include "core.h"

#ifdef __cplusplus
extern "C" {
#endif

struct m19_dm_real {
    int control;
    unsigned major;
    unsigned minor;
};

extern const struct m19_dm_ops m19_dm_real_ops;

#ifdef __cplusplus
}
#endif

#endif
