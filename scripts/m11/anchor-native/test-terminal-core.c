/* Cross-check: the native terminal core must decide a boot's end identically to the frozen,
 * CI-qualified offline custodian over the entire never-mapped state space (no region, no
 * graph, dsp_map_attempted never set). Built ONLY in the offline mode, where both
 * m11_terminal_core_action() and m11_custodian_terminal_action() are linkable in one program.
 * The custodian source is untouched; this proves the native copy has not drifted from it. */
#ifndef M11_OWNERSHIP_OFFLINE
#error "test-terminal-core.c builds only with M11_OWNERSHIP_OFFLINE (links the custodian)"
#endif
#include "terminal_core.h"
#include "../qualification/ownership/m11_custodian.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

/* The custodian decision for a mirror ledger with no region/graph and matching closed /
 * imports-lost state. terminal_action reads only the ledger + closed + kernel_imports_lost +
 * (region/graph, all zero here); mgr is never dereferenced, so a zeroed custodian is valid. */
static m11_terminal_action cust_action(m11_boot_ledger *b, bool closed, bool imports_lost) {
    m11_custodian c; memset(&c, 0, sizeof c);
    c.boot = b; c.closed = closed; c.kernel_imports_lost = imports_lost;
    return m11_custodian_terminal_action(&c);
}

static unsigned checks;
static void same(m11_terminal_core *tc, m11_terminal_action expect) {
    m11_terminal_action core = m11_terminal_core_action(tc);
    m11_terminal_action cust = cust_action(tc->boot, tc->closed_ep && tc->closed_ion,
                                           tc->kernel_imports_lost);
    if (core != cust) {
        fprintf(stderr, "DRIFT core=%s custodian=%s\n",
                m11_terminal_action_name(core), m11_terminal_action_name(cust));
        assert(core == cust);
    }
    assert(core == expect);
    assert(m11_terminal_core_reboot_permitted(tc) ==
           (expect == M11_TERMINAL_ORDERLY_SHUTDOWN));
    checks++;
}

/* Fresh enrolled core over a fresh ledger. Anchors need only be distinct, non-NULL. */
static m11_pid1_anchor A_ep, A_ion;
static void fresh(m11_terminal_core *tc, m11_boot_ledger *b) {
    memset(b, 0, sizeof *b);
    assert(m11_terminal_core_new_boot(b, 0x51u, 1000u) == 0);
    assert(m11_terminal_core_init(tc, b, &A_ep, &A_ion, 5000u) == 0);
    assert(m11_terminal_core_tick(tc, 1000u) == 0);
}

int main(void) {
    m11_terminal_core tc; m11_boot_ledger b;

    /* 1. Clean, nothing closed: both anchors still held -> HOLD. */
    fresh(&tc, &b); same(&tc, M11_TERMINAL_HOLD);

    /* 2. Clean, only the endpoint closed -> still held -> HOLD. */
    fresh(&tc, &b); assert(m11_terminal_core_mark_closed(&tc, &A_ep) == 0);
    same(&tc, M11_TERMINAL_HOLD);

    /* 3. Clean, only ION closed -> HOLD. */
    fresh(&tc, &b); assert(m11_terminal_core_mark_closed(&tc, &A_ion) == 0);
    same(&tc, M11_TERMINAL_HOLD);

    /* 4. Clean, both closed (torn down), never mapped -> ORDERLY_SHUTDOWN. */
    fresh(&tc, &b); m11_terminal_core_mark_closed(&tc, &A_ep);
    m11_terminal_core_mark_closed(&tc, &A_ion);
    same(&tc, M11_TERMINAL_ORDERLY_SHUTDOWN);

    /* 5. Owner exit (imports lost) -> RESET, even torn down. */
    fresh(&tc, &b); m11_terminal_core_mark_closed(&tc, &A_ep);
    m11_terminal_core_mark_closed(&tc, &A_ion);
    m11_terminal_core_owner_exit(&tc, 1100u);
    same(&tc, M11_TERMINAL_RESET_RETAINING_ANCHORS);

    /* 6. Global cleanup (imports lost, owner still alive) -> RESET. */
    fresh(&tc, &b); m11_terminal_core_global_cleanup(&tc, 1100u);
    same(&tc, M11_TERMINAL_RESET_RETAINING_ANCHORS);

    /* 7. PD down -> RESET. */
    fresh(&tc, &b); m11_terminal_core_pd_down(&tc, 1100u);
    same(&tc, M11_TERMINAL_RESET_RETAINING_ANCHORS);

    /* 8. Supervisor (global init) death -> RECOVERY_REQUIRED -> RESET. */
    fresh(&tc, &b); m11_terminal_core_supervisor_exit(&tc, true, 1100u);
    same(&tc, M11_TERMINAL_RESET_RETAINING_ANCHORS);

    /* 9. Supervisor (non-PID1 final holder) death -> UNSAFE_LAST_CLOSE_OCCURRED. */
    fresh(&tc, &b); m11_terminal_core_supervisor_exit(&tc, false, 1100u);
    same(&tc, M11_TERMINAL_UNSAFE_LAST_CLOSE_OCCURRED);

    /* 10. Clock regression on tick -> RECOVERY_REQUIRED -> RESET. */
    fresh(&tc, &b); m11_terminal_core_mark_closed(&tc, &A_ep);
    m11_terminal_core_mark_closed(&tc, &A_ion);
    assert(m11_terminal_core_tick(&tc, 500u) == -ERANGE);
    same(&tc, M11_TERMINAL_RESET_RETAINING_ANCHORS);

    /* 11. Deadline expiry after a taint -> RECOVERY_REQUIRED -> RESET. */
    fresh(&tc, &b); m11_terminal_core_pd_down(&tc, 1100u); /* sets a 5000ms deadline */
    assert(m11_terminal_core_tick(&tc, 1100u + 5000u) != 0);
    same(&tc, M11_TERMINAL_RESET_RETAINING_ANCHORS);

    /* 12. NULL core -> both return RESET (fail-closed). */
    assert(m11_terminal_core_action(NULL) == M11_TERMINAL_RESET_RETAINING_ANCHORS);
    { m11_custodian z; memset(&z, 0, sizeof z);
      assert(m11_custodian_terminal_action(&z) == M11_TERMINAL_RESET_RETAINING_ANCHORS); }
    checks++;

    printf("PASS terminal-core vs custodian: %u terminal decisions identical\n", checks);

    /* ---- cmdline gate equality over a corpus (byte-identical verdicts) ---- */
    static const char *corpus[] = {
        "console=ttyMSM0,115200n8 iommu.strict=1",
        "iommu.strict=0",
        "\"iommu.strict=0\"",
        "iommu.passthrough=1",
        "iommu.passthrough=0 iommu.strict=1",
        "iommu-strict=0",                 /* dash folding */
        "foo=bar -- iommu.strict=0",      /* after -- still rejected (conservative) */
        "a=1 b=2 c=3",
        "",
        "\"",                             /* final lone quote: OOB in pinned next_arg */
        "ok=1 \"",                        /* trailing lone quote */
        "iommu.strict=1 iommu.passthrough=0",
        "quiet splash iommu.strict=1 androidboot.hardware=marble",
        "iommu.passthrough=\"1\"",
        "iommu.strict=",
    };
    unsigned n = sizeof corpus / sizeof *corpus, cm = 0;
    for (unsigned i = 0; i < n; i++) {
        bool a = m11_terminal_core_cmdline_allowed(corpus[i]);
        bool c = m11_custodian_cmdline_allowed(corpus[i]);
        if (a != c) { fprintf(stderr, "cmdline DRIFT [%u] %d!=%d: %s\n", i, a, c, corpus[i]); }
        assert(a == c);
        cm++;
    }
    /* NULL both reject. */
    assert(m11_terminal_core_cmdline_allowed(NULL) == false);
    assert(m11_custodian_cmdline_allowed(NULL) == false);
    printf("PASS terminal-core vs custodian: %u cmdline verdicts identical\n", cm);
    return 0;
}
