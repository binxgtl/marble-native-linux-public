#ifndef M11_OFFLINE_CUSTODIAN_H
#define M11_OFFLINE_CUSTODIAN_H
/* Qualification ONLY. No real endpoint, DMA allocator, PID1 or recovery adapter. */
#ifndef M11_OWNERSHIP_OFFLINE
#error "Custodian requires explicitly offline qualification; device integration is BLOCKED"
#endif
#include "../runtime-repair/m11_shmem.h"

#define M11_CUSTODIAN_REGIONS 4u
typedef enum { M11_ADSP_CLEAN, M11_ADSP_TAINTED, M11_RECOVERY_REQUIRED } m11_adsp_state;
enum {
    M11_TAINT_REMOTE_UNKNOWN = 1u, M11_TAINT_WORKER_EXIT = 2u,
    M11_TAINT_CUSTODIAN_EXIT = 4u, M11_TAINT_GLOBAL_CLEANUP = 8u,
    M11_TAINT_PD_DOWN = 16u, M11_TAINT_CLOCK = 32u,
    M11_TAINT_LOCAL_ERROR = 64u, M11_TAINT_GRAPH_UNKNOWN = 128u
};
/* Separate supervisor-owned boot ledger; NEVER part of a restartable worker.
 * Ordinary RAM is not durable across supervisor/PID1 death. No claim otherwise. */
typedef struct {
    uint64_t boot_epoch, last_ms, recovery_due_ms;
    m11_adsp_state state;
    uint32_t reasons;
    bool initialized, owner_alive, owner_enrolled, recovery_deadline_set;
} m11_boot_ledger;
typedef struct {
    /* These are synthetic model preconditions, NOT a physical admission API. */
    bool exclusive_importer, no_other_endpoint, no_pcm_clients;
    bool strict_iommu, graph_quiescent, nack_atomicity_model;
} m11_custodian_model_contract;
typedef struct {
    m11_boot_ledger *boot;
    m11_shmem_mgr_t *mgr;
    m11_custodian_model_contract contract;
    m11_shmem_region_t regions[M11_CUSTODIAN_REGIONS];
    bool occupied[M11_CUSTODIAN_REGIONS];
    bool kernel_imports_lost; /* external global cleanup/death invalidates local records */
    bool call_inflight, closed;
    uint32_t recovery_budget_ms;
} m11_custodian;

/* Only model creation at a NEW boot. No same-boot reset/restart/taint-clear API. */
int m11_model_new_boot(m11_boot_ledger *, uint64_t epoch, uint64_t now_ms);
int m11_custodian_init(m11_custodian *, m11_boot_ledger *, m11_shmem_mgr_t *,
                       const m11_custodian_model_contract *, uint32_t recovery_budget_ms);
int m11_custodian_map(m11_custodian *, size_t bytes, uint64_t now_ms, unsigned *slot);
int m11_custodian_retire(m11_custodian *, unsigned slot, uint64_t now_ms);
void m11_custodian_worker_exit(m11_custodian *, uint64_t now_ms);
void m11_custodian_owner_exit(m11_custodian *, uint64_t now_ms);
void m11_custodian_global_cleanup(m11_custodian *, uint64_t now_ms);
void m11_custodian_pd_down(m11_custodian *, uint64_t now_ms);
int m11_custodian_tick(m11_custodian *, uint64_t now_ms);
int m11_custodian_close(m11_custodian *);
/* There is no qualified ADSP quiescence/restart boundary. Always -ENOTSUP. */
int m11_custodian_request_recovery(m11_custodian *);
/* Conservative lexical model gate. Does not prove effective vendor-domain strictness. */
bool m11_custodian_cmdline_allowed(const char *cmdline);
#endif
