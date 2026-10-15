#ifndef M11_OFFLINE_CUSTODIAN_H
#define M11_OFFLINE_CUSTODIAN_H
/* Qualification ONLY. No real endpoint, DMA allocator, PID1 or recovery adapter. */
#ifndef M11_OWNERSHIP_OFFLINE
#error "Custodian requires explicitly offline qualification; device integration is BLOCKED"
#endif
#include "../runtime-repair/m11_shmem.h"
#include "../runtime-repair/m11_apm_protocol.h"

/* 3: graph ledger, foreign-traffic latch, engine clock, terminal boundary, next_arg gate.
 * 4: one-shot regions (no MAP after the first DSP UNMAP of a boot) and no reboot(2) after
 *    any DSP MAP of a boot. Both are fail-closed narrowing rules; neither proves ADSP DMA
 *    quiescence. */
#define M11_CUSTODIAN_API_REVISION 4
#define M11_CUSTODIAN_REGIONS 4u
#define M11_CUSTODIAN_GRAPHS 2u
typedef enum { M11_ADSP_CLEAN, M11_ADSP_TAINTED, M11_RECOVERY_REQUIRED } m11_adsp_state;
enum {
    M11_TAINT_REMOTE_UNKNOWN = 1u, M11_TAINT_WORKER_EXIT = 2u,
    M11_TAINT_CUSTODIAN_EXIT = 4u, M11_TAINT_GLOBAL_CLEANUP = 8u,
    M11_TAINT_PD_DOWN = 16u, M11_TAINT_CLOCK = 32u,
    M11_TAINT_LOCAL_ERROR = 64u, M11_TAINT_GRAPH_UNKNOWN = 128u,
    M11_TAINT_FOREIGN_TRAFFIC = 256u
};
/* Separate supervisor-owned boot ledger; NEVER part of a restartable worker.
 * Ordinary RAM is not durable across supervisor/PID1 death. No claim otherwise. */
typedef struct {
    uint64_t boot_epoch, last_ms, recovery_due_ms;
    m11_adsp_state state;
    uint32_t reasons;
    bool initialized, owner_alive, owner_enrolled, recovery_deadline_set;
    /* Model of the final-anchor holder's death (m11_custodian_supervisor_exit). */
    bool supervisor_dead, final_anchor_released;
    /* Set at intent, before the call that may transmit; never cleared in a boot.
     * dsp_map_attempted: a MAP may have reached the ADSP, so this boot never ends with
     *   reboot(2) (device_shutdown() runs the SMMU driver's .shutdown, the ADSP has none,
     *   and quiescence after any ACK is unproven).
     * dsp_unmap_attempted: an UNMAP may have reached the ADSP; its IOVA returns to the
     *   allocator, so no later MAP may receive it while a late DSP access is possible. */
    bool dsp_map_attempted, dsp_unmap_attempted;
} m11_boot_ledger;
typedef struct {
    /* These are synthetic model preconditions, NOT a physical admission API. */
    bool exclusive_importer, no_other_endpoint, no_pcm_clients;
    bool strict_iommu, graph_quiescent, nack_atomicity_model;
    /* The final GPR endpoint / ION / DMA-BUF anchors are held by global init (PID1).
     * Pinned ACK kernel/exit.c:825-859: the last thread of global init panics before
     * exit_mm()/exit_files(), so its death cannot reach the kernel last-close path. */
    bool final_anchor_pid1;
} m11_custodian_model_contract;
/*
 * Graph ledger. Only an ACK matched on token/peer/opcode changes a graph's state.
 * A command whose packet may have reached the ADSP without such an ACK leaves the
 * graph UNKNOWN forever in this boot (the engine does not retain graph slots after a
 * timeout, so no late response can resolve it). Any non-FREE graph pins every mapped
 * region: a running graph may reference data regions that GRAPH_OPEN did not name.
 */
typedef enum {
    M11_GRAPH_FREE = 0, M11_GRAPH_OPEN, M11_GRAPH_PREPARED, M11_GRAPH_STARTED,
    M11_GRAPH_UNKNOWN
} m11_custodian_graph_state;
typedef struct {
    m11_custodian_graph_state state;
    unsigned region;            /* region holding the out-of-band GRAPH_OPEN payload */
    uint32_t num_sgs;
    uint32_t sgs[M11_APM_MAX_SUBGRAPHS_PER_CMD];
} m11_custodian_graph;
/*
 * How this boot may END. Derived from the ledger only; it executes nothing.
 *  ORDERLY_SHUTDOWN   clean, nothing mapped/open, endpoint already closed once, and no
 *                     region was ever DSP-mapped in this boot: reboot(2)/poweroff may
 *                     run device_shutdown().
 *  HOLD               clean but regions/graphs/endpoint still held: orderly teardown
 *                     first. reboot(2) is FORBIDDEN while anything is mapped:
 *                     device_shutdown() runs arm_smmu_device_shutdown() ("disabling
 *                     translation") and the ADSP remoteproc has no .shutdown.
 *  HOLD_RECONCILE     tainted, live owner, before the immutable deadline.
 *  RESET_RETAINING_ANCHORS
 *                     end the boot with the anchors still held: PID1 exits, which
 *                     panics before exit_files(); PANIC_TIMEOUT=-1 then calls
 *                     emergency_restart() without device_shutdown(). Never close an
 *                     anchor, never reboot(2). Also the only end of a boot that ever
 *                     DSP-mapped a region, even after a clean orderly teardown.
 *  UNSAFE_LAST_CLOSE_OCCURRED
 *                     the model recorded that a non-PID1 final-anchor holder died, so
 *                     the kernel release path (CLOSE_ALL + global ION cleanup) ran
 *                     without a proven DSP quiescence. Nothing local can repair it.
 */
typedef enum {
    M11_TERMINAL_ORDERLY_SHUTDOWN = 0,
    M11_TERMINAL_HOLD,
    M11_TERMINAL_HOLD_RECONCILE,
    M11_TERMINAL_RESET_RETAINING_ANCHORS,
    M11_TERMINAL_UNSAFE_LAST_CLOSE_OCCURRED
} m11_terminal_action;
typedef struct {
    m11_boot_ledger *boot;
    m11_shmem_mgr_t *mgr;
    m11_custodian_model_contract contract;
    m11_shmem_region_t regions[M11_CUSTODIAN_REGIONS];
    bool occupied[M11_CUSTODIAN_REGIONS];
    m11_custodian_graph graphs[M11_CUSTODIAN_GRAPHS];
    uint32_t region_graph_refs[M11_CUSTODIAN_REGIONS];
    bool kernel_imports_lost; /* external global cleanup/death invalidates local records */
    bool call_inflight, closed;
    uint32_t recovery_budget_ms;
    /* Engine counters as last left by the custodian itself. Any other advance means a
     * GPR command, open or close bypassed the single owner. */
    uint32_t expected_next_token, expected_open_count, expected_close_count;
} m11_custodian;

/* Only model creation at a NEW boot. No same-boot reset/restart/taint-clear API. */
int m11_model_new_boot(m11_boot_ledger *, uint64_t epoch, uint64_t now_ms);
int m11_custodian_init(m11_custodian *, m11_boot_ledger *, m11_shmem_mgr_t *,
                       const m11_custodian_model_contract *, uint32_t recovery_budget_ms);
/* -EPERM once any DSP UNMAP was attempted in this boot (one-shot regions). */
int m11_custodian_map(m11_custodian *, size_t bytes, uint64_t now_ms, unsigned *slot);
/* Refused for the rest of the boot once FOREIGN_TRAFFIC or GRAPH_UNKNOWN is latched. */
int m11_custodian_retire(m11_custodian *, unsigned slot, uint64_t now_ms);
/* Graph commands are custodian-mediated; workers request them, never send them. */
int m11_custodian_graph_open(m11_custodian *, unsigned region, uint32_t shm_offset,
                             const uint32_t *sub_graph_ids, uint32_t num_sub_graphs,
                             uint64_t now_ms, unsigned *graph);
/* PREPARE/START need a CLEAN boot. STOP/CLOSE are teardown and stay allowed when tainted. */
int m11_custodian_graph_cmd(m11_custodian *, unsigned graph, uint32_t opcode, uint64_t now_ms);
/* Orderly STOP (if started) then CLOSE of every ledger graph; stops at the first failure. */
int m11_custodian_graph_teardown(m11_custodian *, uint64_t now_ms);
void m11_custodian_worker_exit(m11_custodian *, uint64_t now_ms);
void m11_custodian_owner_exit(m11_custodian *, uint64_t now_ms);
void m11_custodian_global_cleanup(m11_custodian *, uint64_t now_ms);
void m11_custodian_pd_down(m11_custodian *, uint64_t now_ms);
/* Model of the final-anchor holder dying. Not callable by anything that survived it. */
void m11_custodian_supervisor_exit(m11_custodian *, bool was_global_init, uint64_t now_ms);
int m11_custodian_tick(m11_custodian *, uint64_t now_ms);
int m11_custodian_close(m11_custodian *);
/* There is no qualified same-boot ADSP quiescence/restart boundary. Always -ENOTSUP. */
int m11_custodian_request_recovery(m11_custodian *);
m11_terminal_action m11_custodian_terminal_action(const m11_custodian *);
bool m11_custodian_reboot_permitted(const m11_custodian *);
/*
 * Lexical gate for the EFFECTIVE kernel command line (/proc/cmdline: CONFIG_CMDLINE
 * extension, bootloader and bootconfig "kernel." keys). Tokenizes exactly like pinned
 * ACK lib/cmdline.c next_arg() (quotes included) and accepts iommu.strict only as "1"
 * and iommu.passthrough only as "0". It also rejects a final token that is a single '"',
 * which the pinned next_arg() reads out of bounds. It does not prove effective
 * vendor-domain policy.
 */
bool m11_custodian_cmdline_allowed(const char *cmdline);
const char *m11_terminal_action_name(m11_terminal_action);
#endif
