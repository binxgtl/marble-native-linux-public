/* R2 path admission of the anchor's Linux backend (no open: m11_anchor_linux_ops only checks the
 * path). The native build admits the endpoint only; the R2 build (M11_ANCHOR_NATIVE_ION) also
 * admits /dev/msm_audio_ion; the ION CMA twin and ALSA nodes are refused in every build. */
#include "m11_anchor_linux.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>

static int admits(const char *path) {
    m11_anchor_linux l; m11_anchor_ops ops;
    return m11_anchor_linux_ops(&l,path,0,&ops);
}
int main(void) {
    assert(!admits("/dev/aud_pasthru_adsp"));
#if defined(M11_ANCHOR_NATIVE_ION)
    assert(!admits("/dev/msm_audio_ion"));
#else
    assert(admits("/dev/msm_audio_ion")==-EPERM);
#endif
    assert(admits("/dev/msm_audio_ion_cma")==-EPERM);
    assert(admits("/dev/msm_audio_ion/")==-EPERM && admits("/dev/./msm_audio_ion")==-EPERM);
    assert(admits("/dev/snd/pcmC0D0p")==-EPERM && admits("/dev/snd/controlC0")==-EPERM);
#if defined(M11_ANCHOR_NATIVE_ION)
    puts("PASS R2 build path admission: endpoint and /dev/msm_audio_ion only; CMA twin and ALSA refused");
#else
    puts("PASS native build path admission: endpoint only; ION, CMA twin and ALSA refused");
#endif
    return 0;
}
