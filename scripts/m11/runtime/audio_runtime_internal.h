#ifndef M11_AUDIO_RUNTIME_INTERNAL_H
#define M11_AUDIO_RUNTIME_INTERNAL_H
#include "audio_runtime.h"
#include "gpr_native.h"
/* Link wrapping these entrypoints is permitted ONLY in synthetic test binaries. */
int m11_audio_admit(struct m11_gpr_session *);
int m11_audio_control(struct m11_gpr_session const *);
void m11_audio_child_detach(struct m11_gpr_session const *);
void m11_audio_finish(struct m11_gpr_session *, const struct m11_gpr_result *);
#endif
