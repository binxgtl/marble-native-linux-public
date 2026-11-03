/* One-shot probe supervision contract. Records contain status only, never keys. */
#ifndef M19_PROBE_H
#define M19_PROBE_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
enum m19_probe_stage { M19_P_READ, M19_P_LOOKUP, M19_P_LEVEL, M19_P_CREATE,
                       M19_P_UPDATE, M19_P_FINISH, M19_P_EPHEMERAL, M19_P_RESULT };
enum m19_upgrade_fact { M19_U_NOT_ATTEMPTED, M19_U_UNKNOWN, M19_U_NONE_OBSERVED, M19_U_OBSERVED };
typedef void (*m19_probe_progress)(void *, enum m19_probe_stage, enum m19_upgrade_fact, int);
typedef int (*m19_probe_worker)(const char *, m19_probe_progress, void *, int *, enum m19_upgrade_fact *, int *);
int m19_probe_supervise(const char *directory, m19_probe_worker worker);
#ifdef __cplusplus
}
#endif
#endif
