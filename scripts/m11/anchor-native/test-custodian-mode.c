/* G1 (docs/m11-custodian-native-integration.md): the reviewed M11_CUSTODIAN_NATIVE build.
 * One translation unit includes the custodian, the PID1 anchor adapter and the native terminal
 * core together (one terminal enum, one boot ledger per program) and links the custodian, its
 * offline-portable engine/shmem cores and the terminal core. It selects the build only: no native
 * backend exists yet (G2/G3). The first output line must equal test-terminal-enum's in the offline
 * and anchor-native builds; the checks below must hold. */
#ifndef M11_CUSTODIAN_NATIVE
#error "test-custodian-mode.c builds only with M11_CUSTODIAN_NATIVE"
#endif
#include "m11_custodian.h"
#include "m11_pid1_anchor.h"
#include "terminal_core.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    printf("ORDERLY_SHUTDOWN=%d HOLD=%d HOLD_RECONCILE=%d RESET_RETAINING_ANCHORS=%d UNSAFE_LAST_CLOSE_OCCURRED=%d\n",
           M11_TERMINAL_ORDERLY_SHUTDOWN, M11_TERMINAL_HOLD, M11_TERMINAL_HOLD_RECONCILE,
           M11_TERMINAL_RESET_RETAINING_ANCHORS, M11_TERMINAL_UNSAFE_LAST_CLOSE_OCCURRED);
    /* Both deciders link and fail closed without a ledger. */
    m11_custodian c; memset(&c, 0, sizeof c);
    assert(m11_custodian_terminal_action(&c) == M11_TERMINAL_RESET_RETAINING_ANCHORS);
    assert(m11_terminal_core_action(NULL) == M11_TERMINAL_RESET_RETAINING_ANCHORS);
    /* The custodian's and the native core's cmdline gates agree in this build too. */
    static const char *cases[] = {"iommu.strict=1", "iommu.strict=0", "iommu.passthrough=1", "\"", "a=1"};
    for (unsigned i = 0; i < sizeof cases / sizeof *cases; i++)
        assert(m11_custodian_cmdline_allowed(cases[i]) == m11_terminal_core_cmdline_allowed(cases[i]));
    /* The terminal core's ledger IS the custodian's ledger type in this build. */
    m11_boot_ledger b; memset(&b, 0, sizeof b);
    assert(m11_model_new_boot(&b, 1u, 0u) == 0);
    assert(b.state == M11_ADSP_CLEAN && b.owner_alive && !b.dsp_map_attempted);
    printf("PASS custodian native build mode: one enum and ledger shared by custodian, anchor and terminal core\n");
    return 0;
}
