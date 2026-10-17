/* Native terminal core — see terminal_core.h. The ledger/taint/tick/lifetime/terminal and
 * cmdline-gate logic is byte-faithful to scripts/m11/qualification/ownership/m11_custodian.c
 * (API rev 4). No shmem / APM / gpr-engine. test-terminal-core.c proves no drift. */
#include "terminal_core.h"
#include <errno.h>
#include <limits.h>
#include <string.h>

/* ------------------------------------------------------------------------------------
 * Kernel command-line gate. Byte-faithful to m11_custodian.c's gate; mirrors pinned ACK
 * b97c62c4 lib/cmdline.c next_arg() and kernel/params.c parse_args()/parameqn().
 * ---------------------------------------------------------------------------------- */
#define M11_CMDLINE_MAX 4096u /* arm64 COMMAND_LINE_SIZE is 2048; longer is malformed */
static bool kspace(unsigned char ch) { return (ch >= 9u && ch <= 13u) || ch == 32u || ch == 160u; }
static char *kskip_spaces(char *s) { while (kspace((unsigned char)*s)) ++s; return s; }
static char *knext_arg(char *args, char **param, char **val) {
    unsigned int i, equals = 0;
    int in_quote = 0, quoted = 0;
    char *next;
    if (*args == '"') { args++; in_quote = 1; quoted = 1; }
    for (i = 0; args[i]; i++) {
        if (kspace((unsigned char)args[i]) && !in_quote) break;
        if (equals == 0) { if (args[i] == '=') equals = i; }
        if (args[i] == '"') in_quote = !in_quote;
    }
    *param = args;
    if (!equals) *val = NULL;
    else {
        args[equals] = '\0';
        *val = args + equals + 1;
        if (**val == '"') {
            (*val)++;
            if (args[i-1] == '"') args[i-1] = '\0';
        }
    }
    if (quoted && i > 0 && args[i-1] == '"') args[i-1] = '\0';
    if (args[i]) { args[i] = '\0'; next = args + i + 1; }
    else next = args + i;
    return kskip_spaces(next);
}
static char kdash(char c) { return c == '-' ? '_' : c; }
static bool kparameq(const char *a, const char *b) {
    size_t n = strlen(b) + 1u;
    for (size_t i = 0; i < n; i++) if (kdash(a[i]) != kdash(b[i])) return false;
    return true;
}
bool m11_terminal_core_cmdline_allowed(const char *cmdline) {
    if (!cmdline) return false;
    size_t len = 0;
    while (len < M11_CMDLINE_MAX && cmdline[len]) ++len;
    if (len >= M11_CMDLINE_MAX) return false;
    char buf[M11_CMDLINE_MAX];
    memcpy(buf, cmdline, len + 1u);
    char *args = kskip_spaces(buf);
    while (*args) {
        char *param, *val;
        /* Pinned ACK next_arg() reads args[i-1] with unsigned i == 0 for a final lone '"':
         * an out-of-bounds read; never accept it (upstream fixed with "i > 0"). */
        if (args[0] == '"' && args[1] == '\0') return false;
        args = knext_arg(args, &param, &val);
        if (kparameq(param, "iommu.strict")) {
            if (!val || strcmp(val, "1") != 0) return false;
        } else if (kparameq(param, "iommu.passthrough")) {
            if (!val || strcmp(val, "0") != 0) return false;
        }
    }
    return true;
}

/* ---------------------------------- ledger ---------------------------------------- */
static void taint(m11_terminal_core *c, uint32_t reason, uint64_t now) {
    m11_boot_ledger *b = c->boot;
    b->reasons |= reason;
    if (b->state == M11_ADSP_CLEAN) b->state = M11_ADSP_TAINTED;
    if (!b->recovery_deadline_set) {
        b->recovery_due_ms = now > UINT64_MAX - c->recovery_budget_ms ?
            UINT64_MAX : now + c->recovery_budget_ms;
        b->recovery_deadline_set = true;
    }
}

int m11_terminal_core_new_boot(m11_boot_ledger *b, uint64_t epoch, uint64_t now) {
    if (!b || !epoch) return -EINVAL;
    if (b->initialized) return -EALREADY;
    *b = (m11_boot_ledger){.boot_epoch=epoch, .last_ms=now,
        .state=M11_ADSP_CLEAN, .initialized=true, .owner_alive=true};
    return 0;
}

int m11_terminal_core_init(m11_terminal_core *c, m11_boot_ledger *b,
                           const m11_pid1_anchor *ep, const m11_pid1_anchor *ion,
                           uint32_t budget) {
    if (!c || !b || !b->initialized || !ep || !ion || ep == ion || !budget)
        return -EINVAL;
    if (b->state != M11_ADSP_CLEAN || !b->owner_alive) return -EOWNERDEAD;
    if (b->owner_enrolled) return -EBUSY;
    *c = (m11_terminal_core){.boot=b, .ep=ep, .ion=ion, .recovery_budget_ms=budget};
    b->owner_enrolled = true;
    return 0;
}

int m11_terminal_core_mark_closed(m11_terminal_core *c, const m11_pid1_anchor *a) {
    if (!c || !a) return -EINVAL;
    if (a == c->ep) { c->closed_ep = true; return 0; }
    if (a == c->ion) { c->closed_ion = true; return 0; }
    return -EINVAL;
}

int m11_terminal_core_tick(m11_terminal_core *c, uint64_t now) {
    if (!c || !c->boot) return -EINVAL;
    if (now < c->boot->last_ms) {
        taint(c, M11_TAINT_CLOCK, c->boot->last_ms);
        c->boot->state = M11_RECOVERY_REQUIRED;
        return -ERANGE;
    }
    c->boot->last_ms = now;
    if (c->boot->recovery_deadline_set && now >= c->boot->recovery_due_ms)
        c->boot->state = M11_RECOVERY_REQUIRED;
    return c->boot->state == M11_RECOVERY_REQUIRED ? -EOWNERDEAD : 0;
}

void m11_terminal_core_owner_exit(m11_terminal_core *c, uint64_t now) {
    if (!c || !c->boot) return;
    c->boot->owner_alive = false;
    c->kernel_imports_lost = true; /* references/import validity UNKNOWN, not clean */
    taint(c, M11_TAINT_CUSTODIAN_EXIT, now);
}
void m11_terminal_core_global_cleanup(m11_terminal_core *c, uint64_t now) {
    if (!c || !c->boot) return;
    c->kernel_imports_lost = true;
    taint(c, M11_TAINT_GLOBAL_CLEANUP, now);
}
void m11_terminal_core_pd_down(m11_terminal_core *c, uint64_t now) {
    if (!c || !c->boot) return;
    taint(c, M11_TAINT_PD_DOWN, now); /* PD DOWN != ADSP DMA quiescence */
    c->kernel_imports_lost = true;
}
void m11_terminal_core_supervisor_exit(m11_terminal_core *c, bool was_global_init, uint64_t now) {
    if (!c || !c->boot) return;
    m11_boot_ledger *b = c->boot;
    b->supervisor_dead = true;
    b->owner_alive = false;
    if (!was_global_init) { b->final_anchor_released = true; c->kernel_imports_lost = true; }
    taint(c, M11_TAINT_CUSTODIAN_EXIT | (was_global_init ? 0u : M11_TAINT_GLOBAL_CLEANUP), now);
    b->state = M11_RECOVERY_REQUIRED;
}

m11_terminal_action m11_terminal_core_action(const m11_terminal_core *c) {
    if (!c || !c->boot) return M11_TERMINAL_RESET_RETAINING_ANCHORS;
    const m11_boot_ledger *b = c->boot;
    if (b->final_anchor_released) return M11_TERMINAL_UNSAFE_LAST_CLOSE_OCCURRED;
    if (b->state == M11_RECOVERY_REQUIRED || !b->owner_alive || c->kernel_imports_lost ||
        (b->recovery_deadline_set && b->last_ms >= b->recovery_due_ms))
        return M11_TERMINAL_RESET_RETAINING_ANCHORS;
    /* Never-mapped: no region, no graph ever. torn_down == both anchors closed once. */
    bool torn_down = c->closed_ep && c->closed_ion;
    /* Present and compiled though unreachable here (dsp_map_attempted is never set): the
     * same guard the custodian uses to refuse reboot(2) after any DSP MAP of a boot. */
    if (torn_down && b->dsp_map_attempted) return M11_TERMINAL_RESET_RETAINING_ANCHORS;
    if (b->state == M11_ADSP_TAINTED) return M11_TERMINAL_HOLD_RECONCILE;
    if (!torn_down) return M11_TERMINAL_HOLD;
    return M11_TERMINAL_ORDERLY_SHUTDOWN;
}

bool m11_terminal_core_reboot_permitted(const m11_terminal_core *c) {
    return m11_terminal_core_action(c) == M11_TERMINAL_ORDERLY_SHUTDOWN;
}
