/* Native terminal core: the boot-ledger + terminal-decision subset of the offline
 * custodian (scripts/m11/qualification/ownership/m11_custodian.{h,c}), with NO shmem /
 * APM / gpr-engine dependency, so it links into the native PID1 runner. Built only with
 * M11_ANCHOR_NATIVE (device integration path) or M11_OWNERSHIP_OFFLINE (cross-check test).
 *
 * This is a never-mapped core: there is no m11_terminal_core_map() and nothing ever sets
 * dsp_map_attempted / dsp_unmap_attempted. The map/graph/retire machinery stays in the
 * offline custodian only. The ledger, taints, lifetime events, tick and terminal decision
 * are byte-faithful to m11_custodian.c; test-terminal-core.c proves they do not drift by
 * comparing this core against m11_custodian_terminal_action() over the never-mapped state
 * space. The custodian itself is unchanged (baseline-pinned). */
#ifndef M11_TERMINAL_CORE_H
#define M11_TERMINAL_CORE_H
#if !defined(M11_ANCHOR_NATIVE) && !defined(M11_OWNERSHIP_OFFLINE)
#error "terminal_core requires M11_ANCHOR_NATIVE (device) or M11_OWNERSHIP_OFFLINE (test)"
#endif
#include "../qualification/ownership/m11_pid1_anchor.h" /* m11_terminal_action, m11_pid1_anchor */
#include <stdbool.h>
#include <stdint.h>

#if defined(M11_OWNERSHIP_OFFLINE)
/* Offline (cross-check) build: reuse the custodian's real ledger and enums verbatim. */
#include "../qualification/ownership/m11_custodian.h"
#else
/* Native build: mirror m11_custodian.h's ledger/adsp_state/taints EXACTLY. Any edit here
 * must be matched in the custodian; test-terminal-core.c fails if the decision diverges. */
typedef enum { M11_ADSP_CLEAN, M11_ADSP_TAINTED, M11_RECOVERY_REQUIRED } m11_adsp_state;
enum {
    M11_TAINT_REMOTE_UNKNOWN = 1u, M11_TAINT_WORKER_EXIT = 2u,
    M11_TAINT_CUSTODIAN_EXIT = 4u, M11_TAINT_GLOBAL_CLEANUP = 8u,
    M11_TAINT_PD_DOWN = 16u, M11_TAINT_CLOCK = 32u,
    M11_TAINT_LOCAL_ERROR = 64u, M11_TAINT_GRAPH_UNKNOWN = 128u,
    M11_TAINT_FOREIGN_TRAFFIC = 256u
};
typedef struct {
    uint64_t boot_epoch, last_ms, recovery_due_ms;
    m11_adsp_state state;
    uint32_t reasons;
    bool initialized, owner_alive, owner_enrolled, recovery_deadline_set;
    bool supervisor_dead, final_anchor_released;
    bool dsp_map_attempted, dsp_unmap_attempted; /* never set on this path */
} m11_boot_ledger;
#endif

/* The never-mapped terminal core. Holds BOTH PID1 anchors (endpoint + ION) so the ledger
 * covers both, as CP2 criterion 7 requires, and records whether each has had its one
 * final close (torn-down). It never maps, so there is no region/graph state at all. */
#define M11_TERMINAL_CORE_API_REVISION 1
typedef struct {
    m11_boot_ledger *boot;
    const m11_pid1_anchor *ep;   /* GPR endpoint anchor */
    const m11_pid1_anchor *ion;  /* /dev/msm_audio_ion anchor */
    bool closed_ep, closed_ion;  /* each set once, after that anchor's final close */
    bool kernel_imports_lost;    /* external global cleanup / owner death invalidates records */
    uint32_t recovery_budget_ms;
} m11_terminal_core;

/* Create the NEW-boot ledger (same semantics as m11_custodian: zeroed NEW storage only). */
int m11_terminal_core_new_boot(m11_boot_ledger *, uint64_t epoch, uint64_t now_ms);
/* Enrol both anchors. Each must be distinct and non-NULL; the boot ledger must be a fresh
 * CLEAN, owner-alive, not-yet-enrolled ledger. Mirrors the custodian's enrol gate for the
 * fields that exist off the map path. */
int m11_terminal_core_init(m11_terminal_core *, m11_boot_ledger *,
                           const m11_pid1_anchor *ep, const m11_pid1_anchor *ion,
                           uint32_t recovery_budget_ms);
/* Record that an anchor has had its single final close. Idempotent per anchor. */
int m11_terminal_core_mark_closed(m11_terminal_core *, const m11_pid1_anchor *);
/* Monotone clock tick; latches RECOVERY_REQUIRED on regression or past the deadline.
 * Byte-faithful to m11_custodian_tick. */
int m11_terminal_core_tick(m11_terminal_core *, uint64_t now_ms);
/* Lifetime events, byte-faithful to the custodian's. */
void m11_terminal_core_owner_exit(m11_terminal_core *, uint64_t now_ms);
void m11_terminal_core_global_cleanup(m11_terminal_core *, uint64_t now_ms);
void m11_terminal_core_pd_down(m11_terminal_core *, uint64_t now_ms);
void m11_terminal_core_supervisor_exit(m11_terminal_core *, bool was_global_init, uint64_t now_ms);
/* How this boot may end. Identical logic to m11_custodian_terminal_action() with no region
 * or graph held (never-mapped): a clean torn-down boot is ORDERLY_SHUTDOWN. */
m11_terminal_action m11_terminal_core_action(const m11_terminal_core *);
bool m11_terminal_core_reboot_permitted(const m11_terminal_core *);

/* Lexical gate for the EFFECTIVE /proc/cmdline. Byte-identical to
 * m11_custodian_cmdline_allowed(); test-terminal-core.c proves equality over a corpus. */
bool m11_terminal_core_cmdline_allowed(const char *cmdline);

#endif
