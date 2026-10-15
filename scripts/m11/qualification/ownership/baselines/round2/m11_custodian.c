#include "m11_custodian.h"
#include <errno.h>
#include <limits.h>
#include <string.h>

static bool pending(const m11_gpr_engine_t *gpr) {
    for (unsigned i=0;i<M11_GPR_MAX_PENDING;i++) if (gpr->slots[i].in_use) return true;
    return false;
}

bool m11_custodian_cmdline_allowed(const char *cmdline) {
    if (!cmdline) return false;
    const char *p=cmdline;
    while (*p) {
        while (*p==' ' || *p=='\t' || *p=='\n') ++p;
        const char *start=p;
        while (*p && *p!=' ' && *p!='\t' && *p!='\n') ++p;
        size_t len=(size_t)(p-start);
        const char key[]="iommu.strict=";
        if (len>=sizeof(key)-1 && !memcmp(start,key,sizeof(key)-1)) {
            /* Reject duplicates with a relaxed value, malformed and alternate booleans. */
            if (len!=sizeof(key) || start[sizeof(key)-1]!='1') return false;
        }
    }
    return true;
}

static void taint(m11_custodian *c, uint32_t reason, uint64_t now) {
    m11_boot_ledger *b = c->boot;
    b->reasons |= reason;
    if (b->state == M11_ADSP_CLEAN) b->state = M11_ADSP_TAINTED;
    if (!b->recovery_deadline_set) {
        b->recovery_due_ms = now > UINT64_MAX - c->recovery_budget_ms ?
            UINT64_MAX : now + c->recovery_budget_ms;
        b->recovery_deadline_set = true;
    }
}
int m11_model_new_boot(m11_boot_ledger *b, uint64_t epoch, uint64_t now) {
    if (!b || !epoch) return -EINVAL;
    /* Caller supplies zeroed NEW storage; do not erase an existing boot ledger. */
    if (b->initialized) return -EALREADY;
    *b = (m11_boot_ledger){.boot_epoch=epoch, .last_ms=now,
        .state=M11_ADSP_CLEAN, .initialized=true, .owner_alive=true};
    return 0;
}
int m11_custodian_init(m11_custodian *c, m11_boot_ledger *b, m11_shmem_mgr_t *mgr,
                       const m11_custodian_model_contract *ct, uint32_t budget) {
    if (!c || !b || !b->initialized || !mgr || !mgr->gpr || !ct || !budget)
        return -EINVAL;
    if (b->state != M11_ADSP_CLEAN || !b->owner_alive) return -EOWNERDEAD;
    if (b->owner_enrolled) return -EBUSY;
    if (!ct->exclusive_importer || !ct->no_other_endpoint || !ct->no_pcm_clients ||
        !ct->strict_iommu || !ct->graph_quiescent || !ct->nack_atomicity_model)
        return -EPERM;
    /* Do not adopt a manager whose import/token registry belongs to another owner. */
    if (m11_shmem_mgr_audit(mgr, NULL, 0) || pending(mgr->gpr))
        return -EBUSY;
    if (!mgr->gpr->is_open || mgr->gpr->pdr_down) return -ENOTCONN;
    *c = (m11_custodian){.boot=b, .mgr=mgr, .contract=*ct,
                         .recovery_budget_ms=budget};
    b->owner_enrolled=true;
    return 0;
}
int m11_custodian_tick(m11_custodian *c, uint64_t now) {
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
static bool retained(const m11_shmem_region_t *r) {
    return r->state != M11_SHMEM_STATE_RELEASED &&
           r->state != M11_SHMEM_STATE_NOT_ALLOCATED;
}
static bool foreign_pending(const m11_custodian *c) {
    for (unsigned s=0;s<M11_GPR_MAX_PENDING;s++) {
        const m11_gpr_slot_t *slot=&c->mgr->gpr->slots[s];
        if (!slot->in_use) continue;
        bool owned=false;
        for (unsigned i=0;i<M11_CUSTODIAN_REGIONS;i++) {
            if (c->occupied[i] && slot->orphaned &&
                c->regions[i].state==M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED &&
                c->regions[i].orphan_token==slot->token) owned=true;
        }
        if (!owned) return true;
    }
    return false;
}
int m11_custodian_map(m11_custodian *c, size_t bytes, uint64_t now, unsigned *slot) {
    if (!c || !slot) return -EINVAL;
    *slot = UINT_MAX;
    int rc = m11_custodian_tick(c, now);
    if (rc) return rc;
    if (c->closed || c->boot->state != M11_ADSP_CLEAN || !c->boot->owner_alive || c->kernel_imports_lost)
        return -EOWNERDEAD;
    if (c->call_inflight || !c->contract.graph_quiescent) return -EBUSY;
    if (c->mgr->gpr->pdr_down) { m11_custodian_pd_down(c, now); return -ENETRESET; }
    if (m11_gpr_engine_orphan_count(c->mgr->gpr)) {
        taint(c,M11_TAINT_REMOTE_UNKNOWN,now); return -EOWNERDEAD;
    }
    if (pending(c->mgr->gpr)) return -EBUSY;
    if (m11_shmem_mgr_audit(c->mgr, c->regions, M11_CUSTODIAN_REGIONS)) {
        taint(c, M11_TAINT_GLOBAL_CLEANUP, now); return -EUCLEAN;
    }
    unsigned i;
    for (i=0; i<M11_CUSTODIAN_REGIONS && c->occupied[i]; ++i) {}
    if (i==M11_CUSTODIAN_REGIONS) return -ENOSPC;
    /* Owner stores the region before allocation/import/TX. Workers never own fds/tokens. */
    c->occupied[i]=true; c->call_inflight=true; *slot=i;
    rc=m11_shmem_alloc_and_map(c->mgr, M11_SHMEM_MODE_DMA_ION_OFFSET, bytes,
                              false, &c->regions[i]);
    c->call_inflight=false;
    if (c->regions[i].state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED)
        taint(c, M11_TAINT_REMOTE_UNKNOWN, now);
    if (c->regions[i].cleanup_error ||
        c->regions[i].state == M11_SHMEM_STATE_LOCAL_RELEASE_PENDING)
        taint(c, M11_TAINT_LOCAL_ERROR, now);
    if (!retained(&c->regions[i])) c->occupied[i]=false;
    return rc;
}
int m11_custodian_retire(m11_custodian *c, unsigned i, uint64_t now) {
    if (!c || i>=M11_CUSTODIAN_REGIONS || !c->occupied[i]) return -EINVAL;
    int rc=m11_custodian_tick(c, now);
    if (rc) return rc;
    if (!c->boot->owner_alive || c->kernel_imports_lost) return -EOWNERDEAD;
    if (c->call_inflight) return -EBUSY;
    if (!c->contract.graph_quiescent || foreign_pending(c)) {
        taint(c, M11_TAINT_GRAPH_UNKNOWN, now); return -EBUSY;
    }
    /* One finite budget shared by late-MAP reconciliation and subsequent UNMAP.
     * Real blocking syscalls still need an independently qualified adapter. */
    uint32_t budget=c->mgr->timeout_ms;
    if (c->boot->recovery_deadline_set) {
        uint64_t left=c->boot->recovery_due_ms-now;
        if (left<budget) budget=(uint32_t)left;
    }
    if (!budget) return -EOWNERDEAD;
    uint64_t start=m11_gpr_monotonic_ms(NULL);
    uint32_t original=c->mgr->timeout_ms;
    c->mgr->timeout_ms=budget; c->call_inflight=true;
    m11_shmem_region_t *r=&c->regions[i];
    rc=0;
    if (r->state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED) {
        rc=m11_shmem_reconcile(c->mgr,r,budget);
        uint64_t elapsed=m11_gpr_monotonic_ms(NULL)-start;
        if (!rc && r->state == M11_SHMEM_STATE_DSP_MAP_ACKNOWLEDGED) {
            if (elapsed>=budget) rc=-ETIMEDOUT;
            else c->mgr->timeout_ms=budget-(uint32_t)elapsed;
        }
    }
    if (!rc && retained(r)) rc=m11_shmem_unmap_and_free(c->mgr,r);
    c->mgr->timeout_ms=original; c->call_inflight=false;
    if (r->state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED)
        taint(c,M11_TAINT_REMOTE_UNKNOWN,now);
    if (r->cleanup_error || r->state == M11_SHMEM_STATE_LOCAL_RELEASE_PENDING)
        taint(c,M11_TAINT_LOCAL_ERROR,now);
    if (!retained(r)) c->occupied[i]=false;
    /* A late ACK can resolve a region. It NEVER clears the boot taint. */
    return rc ? rc : r->cleanup_error;
}
void m11_custodian_worker_exit(m11_custodian *c, uint64_t now) {
    if (!c || !c->boot) return;
    /* Lost worker intent may include unfinished graph work. No implicit UNMAP. */
    taint(c, M11_TAINT_WORKER_EXIT, now);
}
void m11_custodian_owner_exit(m11_custodian *c, uint64_t now) {
    if (!c || !c->boot) return;
    c->boot->owner_alive=false;
    c->kernel_imports_lost=true; /* references/import validity is UNKNOWN, not clean */
    taint(c,M11_TAINT_CUSTODIAN_EXIT,now);
}
void m11_custodian_global_cleanup(m11_custodian *c, uint64_t now) {
    if (!c || !c->boot) return;
    c->kernel_imports_lost=true;
    taint(c,M11_TAINT_GLOBAL_CLEANUP,now);
}
void m11_custodian_pd_down(m11_custodian *c, uint64_t now) {
    if (!c || !c->boot) return;
    taint(c,M11_TAINT_PD_DOWN,now); /* PD DOWN != ADSP DMA quiescence */
    c->kernel_imports_lost=true;
}
int m11_custodian_close(m11_custodian *c) {
    if (!c || !c->boot) return -EINVAL;
    if (c->closed) return -EALREADY;
    if (c->boot->state != M11_ADSP_CLEAN || !c->boot->owner_alive ||
        c->kernel_imports_lost || c->call_inflight) return -EOWNERDEAD;
    if (!c->contract.graph_quiescent) {
        taint(c,M11_TAINT_GRAPH_UNKNOWN,c->boot->last_ms); return -EBUSY;
    }
    for (unsigned i=0;i<M11_CUSTODIAN_REGIONS;i++) if (c->occupied[i]) return -EBUSY;
    if (m11_shmem_mgr_audit(c->mgr,c->regions,M11_CUSTODIAN_REGIONS) ||
        pending(c->mgr->gpr)) return -EBUSY;
    int rc=m11_gpr_engine_close(c->mgr->gpr); /* mock only; physical last-close BLOCKED */
    c->closed=true; /* Do not retry a possibly consumed fd or reopen in this boot. */
    if (rc) taint(c,M11_TAINT_LOCAL_ERROR,c->boot->last_ms);
    return rc;
}
int m11_custodian_request_recovery(m11_custodian *c) {
    if (!c || !c->boot) return -EINVAL;
    return -ENOTSUP; /* No caller boolean, CLOSE_ALL, PDR UP or elapsed time clears taint. */
}
