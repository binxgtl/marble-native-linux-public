#include "m11_custodian.h"
#include <errno.h>
#include <limits.h>
#include <string.h>

static bool pending(const m11_gpr_engine_t *gpr) {
    for (unsigned i=0;i<M11_GPR_MAX_PENDING;i++) if (gpr->slots[i].in_use) return true;
    return false;
}

/* ------------------------------------------------------------------------------------
 * Kernel command-line gate. Mirrors pinned ACK b97c62c4 lib/cmdline.c next_arg()
 * (lines 201-245) and kernel/params.c parse_args()/parameqn() (lines 77-90, 160-186).
 * ---------------------------------------------------------------------------------- */
#define M11_CMDLINE_MAX 4096u /* arm64 COMMAND_LINE_SIZE is 2048; longer is malformed */
/* include/linux/ctype.h _S class: 9-13, 32 and 160 (0xA0). */
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
bool m11_custodian_cmdline_allowed(const char *cmdline) {
    if (!cmdline) return false;
    size_t len = 0;
    while (len < M11_CMDLINE_MAX && cmdline[len]) ++len; /* bounded; no strnlen in strict C11 */
    if (len >= M11_CMDLINE_MAX) return false;
    char buf[M11_CMDLINE_MAX];
    memcpy(buf, cmdline, len + 1u);
    char *args = kskip_spaces(buf);
    while (*args) {
        char *param, *val;
        /* Pinned ACK next_arg() (lib/cmdline.c:238) evaluates args[i-1] with unsigned i == 0
         * when the final token is exactly one '"': an out-of-bounds read ~4 GiB past the
         * buffer, and a write if that byte is '"'. Upstream fixed it with "i > 0" ("lib/cmdline:
         * avoid page fault in next_arg"); the pinned kernel did not. Never accept that input. */
        if (args[0] == '"' && args[1] == '\0') return false;
        args = knext_arg(args, &param, &val);
        /* Kernel stops at "--" and hands the rest to init. Stay conservative anyway:
         * a relaxed IOMMU option after "--" is still rejected below. */
        if (kparameq(param, "iommu.strict")) {
            if (!val || strcmp(val, "1") != 0) return false;
        } else if (kparameq(param, "iommu.passthrough")) {
            /* kstrtobool true selects IOMMU_DOMAIN_IDENTITY (iommu.c iommu_set_def_domain_type):
             * no translation, so the ADSP would address physical memory directly. */
            if (!val || strcmp(val, "0") != 0) return false;
        }
    }
    return true;
}

/* ------------------------------------------------------------------------------------ */
static uint64_t engine_now(const m11_gpr_engine_t *g) {
    /* Same clock the engine's deadline loop uses (m11_gpr_engine.c engine_now_ms). */
    return g->clock_fn ? g->clock_fn(g->clock_user) : m11_gpr_monotonic_ms(NULL);
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
static void observe_own(m11_custodian *c) {
    const m11_gpr_engine_t *g = c->mgr->gpr;
    c->expected_next_token = g->next_token;
    c->expected_open_count = g->open_count;
    c->expected_close_count = g->close_count;
}
/* A token consumed, or an open/close performed, by anyone but the custodian means the
 * single-owner precondition is broken: graph and mapping state are no longer knowable. */
static bool foreign_traffic(m11_custodian *c, uint64_t now) {
    const m11_gpr_engine_t *g = c->mgr->gpr;
    if (g->next_token == c->expected_next_token && g->open_count == c->expected_open_count &&
        g->close_count == c->expected_close_count) return false;
    taint(c, M11_TAINT_FOREIGN_TRAFFIC | M11_TAINT_REMOTE_UNKNOWN | M11_TAINT_GRAPH_UNKNOWN, now);
    observe_own(c); /* report once; the taint itself is permanent */
    return true;
}
static bool graphs_active(const m11_custodian *c) {
    for (unsigned g=0; g<M11_CUSTODIAN_GRAPHS; g++)
        if (c->graphs[g].state != M11_GRAPH_FREE) return true;
    return false;
}
static bool any_region(const m11_custodian *c) {
    for (unsigned i=0; i<M11_CUSTODIAN_REGIONS; i++) if (c->occupied[i]) return true;
    return false;
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
        !ct->strict_iommu || !ct->graph_quiescent || !ct->nack_atomicity_model ||
        !ct->final_anchor_pid1)
        return -EPERM;
    /* Do not adopt a manager whose import/token registry belongs to another owner. */
    if (m11_shmem_mgr_audit(mgr, NULL, 0) || pending(mgr->gpr))
        return -EBUSY;
    if (!mgr->gpr->is_open || mgr->gpr->pdr_down) return -ENOTCONN;
    *c = (m11_custodian){.boot=b, .mgr=mgr, .contract=*ct,
                         .recovery_budget_ms=budget};
    observe_own(c);
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
/* Remaining finite wait: the per-call timeout, never beyond the immutable deadline. */
static uint32_t wait_budget(const m11_custodian *c, uint64_t now) {
    uint32_t budget=c->mgr->timeout_ms;
    if (c->boot->recovery_deadline_set) {
        uint64_t left=c->boot->recovery_due_ms-now;
        if (left<budget) budget=(uint32_t)left;
    }
    return budget;
}
int m11_custodian_map(m11_custodian *c, size_t bytes, uint64_t now, unsigned *slot) {
    if (!c || !slot) return -EINVAL;
    *slot = UINT_MAX;
    int rc = m11_custodian_tick(c, now);
    if (rc) return rc;
    if (foreign_traffic(c, now)) return -EOWNERDEAD;
    if (c->closed || c->boot->state != M11_ADSP_CLEAN || !c->boot->owner_alive || c->kernel_imports_lost)
        return -EOWNERDEAD;
    if (c->call_inflight || !c->contract.graph_quiescent) return -EBUSY;
    /* One-shot regions: an UNMAP may have reached the ADSP and freed its IOVA. No ACK is
     * proven to mean that ADSP DMA stopped, so no later MAP may be given that IOVA. */
    if (c->boot->dsp_unmap_attempted) return -EPERM;
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
    c->boot->dsp_map_attempted=true; /* intent before allocation/import/TX */
    rc=m11_shmem_alloc_and_map(c->mgr, M11_SHMEM_MODE_DMA_ION_OFFSET, bytes,
                              false, &c->regions[i]);
    c->call_inflight=false; observe_own(c);
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
    if (foreign_traffic(c, now)) return -EBUSY;
    if (!c->boot->owner_alive || c->kernel_imports_lost) return -EOWNERDEAD;
    if (c->call_inflight) return -EBUSY;
    /* foreign_traffic() reports a bypass only once; the latched reason must be read on
     * EVERY later call. After undeclared GPR traffic or an unknowable graph state, no
     * graph use of any region can be excluded for the rest of the boot: never UNMAP. */
    if (c->boot->reasons & (M11_TAINT_FOREIGN_TRAFFIC | M11_TAINT_GRAPH_UNKNOWN)) return -EBUSY;
    if (!c->contract.graph_quiescent || foreign_pending(c)) {
        taint(c, M11_TAINT_GRAPH_UNKNOWN, now); return -EBUSY;
    }
    /* Stock GSL closes graphs before it unmaps shared memory. Any OPEN/PREPARED/STARTED
     * or UNKNOWN graph may still reference this region (OOB payload or data path). */
    if (graphs_active(c) || c->region_graph_refs[i]) return -EBUSY;
    /* One finite budget shared by late-MAP reconciliation and subsequent UNMAP.
     * Real blocking syscalls still need an independently qualified adapter. */
    uint32_t budget=wait_budget(c, now);
    if (!budget) return -EOWNERDEAD;
    uint64_t start=engine_now(c->mgr->gpr);
    uint32_t original=c->mgr->timeout_ms;
    c->mgr->timeout_ms=budget; c->call_inflight=true;
    m11_shmem_region_t *r=&c->regions[i];
    rc=0;
    if (r->state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED) {
        rc=m11_shmem_reconcile(c->mgr,r,budget);
        uint64_t now_engine=engine_now(c->mgr->gpr);
        uint64_t elapsed=now_engine>=start ? now_engine-start : (uint64_t)budget;
        if (!rc && r->state == M11_SHMEM_STATE_DSP_MAP_ACKNOWLEDGED) {
            if (elapsed>=budget) rc=-ETIMEDOUT;
            else c->mgr->timeout_ms=budget-(uint32_t)elapsed;
        }
    }
    if (!rc && retained(r)) {
        c->boot->dsp_unmap_attempted=true; /* intent before the call that may transmit */
        rc=m11_shmem_unmap_and_free(c->mgr,r);
    }
    c->mgr->timeout_ms=original; c->call_inflight=false; observe_own(c);
    if (r->state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED)
        taint(c,M11_TAINT_REMOTE_UNKNOWN,now);
    if (r->cleanup_error || r->state == M11_SHMEM_STATE_LOCAL_RELEASE_PENDING)
        taint(c,M11_TAINT_LOCAL_ERROR,now);
    if (!retained(r)) c->occupied[i]=false;
    /* A late ACK can resolve a region. It NEVER clears the boot taint. */
    return rc ? rc : r->cleanup_error;
}

/* ---------------------------------- graph ledger ---------------------------------- */
static bool sgs_overlap(const m11_custodian *c, const uint32_t *sgs, uint32_t n) {
    for (unsigned g=0; g<M11_CUSTODIAN_GRAPHS; g++) {
        const m11_custodian_graph *gr=&c->graphs[g];
        if (gr->state == M11_GRAPH_FREE) continue;
        for (uint32_t a=0; a<gr->num_sgs; a++)
            for (uint32_t b=0; b<n; b++) if (gr->sgs[a]==sgs[b]) return true;
    }
    return false;
}
static void graph_release(m11_custodian *c, m11_custodian_graph *gr) {
    if (gr->region < M11_CUSTODIAN_REGIONS && c->region_graph_refs[gr->region])
        c->region_graph_refs[gr->region]--;
    *gr = (m11_custodian_graph){.state=M11_GRAPH_FREE, .region=UINT_MAX};
}
/* Classify one delivered-or-not graph command. Only a matched ACK advances state; a
 * matched NACK keeps the previous state (atomic-NACK MODEL, required at enrollment);
 * anything that may have reached the ADSP without a matched reply is UNKNOWN. */
static int graph_outcome(m11_custodian *c, m11_custodian_graph *gr, int rc,
                         m11_custodian_graph_state from, m11_custodian_graph_state to,
                         uint64_t now) {
    m11_gpr_tx_status_t tx=c->mgr->gpr->last_tx_status;
    if (rc == 0) {
        if (to == M11_GRAPH_FREE) graph_release(c, gr); else gr->state = to;
        return 0;
    }
    if (tx == M11_GPR_TX_NOT_ATTEMPTED ||
        (tx == M11_GPR_TX_SENT && rc == -EREMOTEIO && c->contract.nack_atomicity_model)) {
        if (from == M11_GRAPH_FREE) graph_release(c, gr); else gr->state = from;
        return rc;
    }
    gr->state = M11_GRAPH_UNKNOWN;
    taint(c, M11_TAINT_GRAPH_UNKNOWN | M11_TAINT_REMOTE_UNKNOWN, now);
    return rc;
}
int m11_custodian_graph_open(m11_custodian *c, unsigned r, uint32_t off,
                             const uint32_t *sgs, uint32_t n, uint64_t now, unsigned *out) {
    if (!c || !out || !sgs) return -EINVAL;
    *out = UINT_MAX;
    int rc = m11_custodian_tick(c, now);
    if (rc) return rc;
    if (foreign_traffic(c, now)) return -EOWNERDEAD;
    if (c->closed || c->boot->state != M11_ADSP_CLEAN || !c->boot->owner_alive || c->kernel_imports_lost)
        return -EOWNERDEAD;
    if (c->call_inflight) return -EBUSY;
    if (r >= M11_CUSTODIAN_REGIONS || !c->occupied[r] ||
        c->regions[r].state != M11_SHMEM_STATE_DSP_MAP_ACKNOWLEDGED) return -EINVAL;
    if (!n || n > M11_APM_MAX_SUBGRAPHS_PER_CMD) return -EINVAL;
    if (sgs_overlap(c, sgs, n)) return -EEXIST;
    unsigned g;
    for (g=0; g<M11_CUSTODIAN_GRAPHS && c->graphs[g].state != M11_GRAPH_FREE; ++g) {}
    if (g == M11_CUSTODIAN_GRAPHS) return -ENOSPC;
    m11_custodian_graph *gr=&c->graphs[g];
    /* Intent before TX: the graph is UNKNOWN and its region pinned until an outcome. */
    *gr = (m11_custodian_graph){.state=M11_GRAPH_UNKNOWN, .region=r, .num_sgs=n};
    memcpy(gr->sgs, sgs, n*sizeof(*sgs));
    c->region_graph_refs[r]++;
    uint32_t status=0;
    c->call_inflight=true; c->mgr->gpr->last_tx_status=M11_GPR_TX_NOT_ATTEMPTED;
    rc=m11_apm_transact_graph_open_region(c->mgr->gpr, c->mgr, &c->regions[r], off, sgs, n,
                                          wait_budget(c, now), &status);
    c->call_inflight=false; observe_own(c);
    if (c->regions[r].cleanup_error) taint(c, M11_TAINT_LOCAL_ERROR, now);
    rc=graph_outcome(c, gr, rc, M11_GRAPH_FREE, M11_GRAPH_OPEN, now);
    if (gr->state != M11_GRAPH_FREE) *out = g;
    return rc;
}
int m11_custodian_graph_cmd(m11_custodian *c, unsigned g, uint32_t op, uint64_t now) {
    if (!c || g >= M11_CUSTODIAN_GRAPHS) return -EINVAL;
    m11_custodian_graph_state from, to;
    bool teardown=false;
    switch (op) {
    case M11_APM_CMD_GRAPH_PREPARE: from=M11_GRAPH_OPEN; to=M11_GRAPH_PREPARED; break;
    case M11_APM_CMD_GRAPH_START: from=M11_GRAPH_PREPARED; to=M11_GRAPH_STARTED; break;
    case M11_APM_CMD_GRAPH_STOP: from=M11_GRAPH_STARTED; to=M11_GRAPH_PREPARED; teardown=true; break;
    case M11_APM_CMD_GRAPH_CLOSE: from=M11_GRAPH_PREPARED; to=M11_GRAPH_FREE; teardown=true; break;
    default: return -EINVAL;
    }
    int rc=m11_custodian_tick(c, now);
    if (rc) return rc;
    if (foreign_traffic(c, now)) return -EOWNERDEAD;
    if (c->closed || !c->boot->owner_alive || c->kernel_imports_lost) return -EOWNERDEAD;
    if (!teardown && c->boot->state != M11_ADSP_CLEAN) return -EOWNERDEAD;
    if (c->call_inflight) return -EBUSY;
    m11_custodian_graph *gr=&c->graphs[g];
    if (gr->state == M11_GRAPH_UNKNOWN) return -EOWNERDEAD;
    /* CLOSE is accepted from OPEN or PREPARED (stopped); a STARTED graph is stopped first. */
    if (op == M11_APM_CMD_GRAPH_CLOSE && gr->state == M11_GRAPH_OPEN) from=M11_GRAPH_OPEN;
    if (gr->state != from) return -EPROTO;
    uint32_t budget=wait_budget(c, now);
    if (!budget) return -EOWNERDEAD;
    gr->state=M11_GRAPH_UNKNOWN; /* intent recorded before TX */
    uint32_t status=0;
    c->call_inflight=true; c->mgr->gpr->last_tx_status=M11_GPR_TX_NOT_ATTEMPTED;
    rc=m11_apm_transact_graph_mgmt(c->mgr->gpr, op, gr->sgs, gr->num_sgs, budget, &status);
    c->call_inflight=false; observe_own(c);
    return graph_outcome(c, gr, rc, from, to, now);
}
int m11_custodian_graph_teardown(m11_custodian *c, uint64_t now) {
    if (!c || !c->boot) return -EINVAL;
    for (unsigned g=0; g<M11_CUSTODIAN_GRAPHS; g++) {
        m11_custodian_graph *gr=&c->graphs[g];
        if (gr->state == M11_GRAPH_FREE) continue;
        if (gr->state == M11_GRAPH_UNKNOWN) return -EOWNERDEAD;
        int rc;
        if (gr->state == M11_GRAPH_STARTED &&
            (rc=m11_custodian_graph_cmd(c, g, M11_APM_CMD_GRAPH_STOP, now))) return rc;
        if ((rc=m11_custodian_graph_cmd(c, g, M11_APM_CMD_GRAPH_CLOSE, now))) return rc;
    }
    return 0;
}

/* ------------------------------- lifetime events ---------------------------------- */
void m11_custodian_worker_exit(m11_custodian *c, uint64_t now) {
    if (!c || !c->boot) return;
    /* Lost worker intent. No implicit UNMAP: retire stays refused until the live
     * custodian has closed every ledger graph with a matched ACK (graph_teardown). */
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
void m11_custodian_supervisor_exit(m11_custodian *c, bool was_global_init, uint64_t now) {
    if (!c || !c->boot) return;
    m11_boot_ledger *b=c->boot;
    /* Global init: do_exit() panics at exit.c:832-833, before exit_mm() (:851) and
     * exit_files() (:859). No fput, no audio_pkt_release, no CLOSE_ALL, no ION free;
     * panic() then calls emergency_restart() (panic.c:404-412), which never runs
     * device_shutdown() (reboot.c:66-70 vs 74-79). Any other final holder reaches
     * exit_files() and the kernel last-close path. */
    b->supervisor_dead=true;
    b->owner_alive=false;
    if (!was_global_init) { b->final_anchor_released=true; c->kernel_imports_lost=true; }
    taint(c, M11_TAINT_CUSTODIAN_EXIT | (was_global_init ? 0u : M11_TAINT_GLOBAL_CLEANUP), now);
    b->state=M11_RECOVERY_REQUIRED;
}
int m11_custodian_close(m11_custodian *c) {
    if (!c || !c->boot) return -EINVAL;
    if (c->closed) return -EALREADY;
    if (foreign_traffic(c, c->boot->last_ms)) return -EOWNERDEAD;
    if (c->boot->state != M11_ADSP_CLEAN || !c->boot->owner_alive ||
        c->kernel_imports_lost || c->call_inflight) return -EOWNERDEAD;
    if (!c->contract.graph_quiescent) {
        taint(c,M11_TAINT_GRAPH_UNKNOWN,c->boot->last_ms); return -EBUSY;
    }
    /* Last-close runs CLOSE_ALL + the global ION crash handler: only with nothing open. */
    if (graphs_active(c) || any_region(c)) return -EBUSY;
    if (m11_shmem_mgr_audit(c->mgr,c->regions,M11_CUSTODIAN_REGIONS) ||
        pending(c->mgr->gpr)) return -EBUSY;
    int rc=m11_gpr_engine_close(c->mgr->gpr); /* mock only; physical last-close BLOCKED */
    observe_own(c);
    c->closed=true; /* Do not retry a possibly consumed fd or reopen in this boot. */
    if (rc) taint(c,M11_TAINT_LOCAL_ERROR,c->boot->last_ms);
    return rc;
}
int m11_custodian_request_recovery(m11_custodian *c) {
    if (!c || !c->boot) return -EINVAL;
    return -ENOTSUP; /* No caller boolean, CLOSE_ALL, PDR UP or elapsed time clears taint. */
}
m11_terminal_action m11_custodian_terminal_action(const m11_custodian *c) {
    if (!c || !c->boot) return M11_TERMINAL_RESET_RETAINING_ANCHORS;
    const m11_boot_ledger *b=c->boot;
    if (b->final_anchor_released) return M11_TERMINAL_UNSAFE_LAST_CLOSE_OCCURRED;
    if (b->state == M11_RECOVERY_REQUIRED || !b->owner_alive || c->kernel_imports_lost ||
        (b->recovery_deadline_set && b->last_ms >= b->recovery_due_ms))
        return M11_TERMINAL_RESET_RETAINING_ANCHORS;
    bool torn_down = !any_region(c) && !graphs_active(c) && c->closed;
    /* A clean orderly teardown does not prove ADSP quiescence; device_shutdown() must not
     * run after any DSP MAP of this boot. Once torn down nothing is left to reconcile and
     * nothing can be mapped again, so this decision is final even if a taint follows. */
    if (torn_down && b->dsp_map_attempted) return M11_TERMINAL_RESET_RETAINING_ANCHORS;
    if (b->state == M11_ADSP_TAINTED) return M11_TERMINAL_HOLD_RECONCILE;
    if (!torn_down) return M11_TERMINAL_HOLD;
    return M11_TERMINAL_ORDERLY_SHUTDOWN;
}
bool m11_custodian_reboot_permitted(const m11_custodian *c) {
    return m11_custodian_terminal_action(c) == M11_TERMINAL_ORDERLY_SHUTDOWN;
}
const char *m11_terminal_action_name(m11_terminal_action a) {
    switch (a) {
    case M11_TERMINAL_ORDERLY_SHUTDOWN: return "ORDERLY_SHUTDOWN";
    case M11_TERMINAL_HOLD: return "HOLD";
    case M11_TERMINAL_HOLD_RECONCILE: return "HOLD_RECONCILE";
    case M11_TERMINAL_RESET_RETAINING_ANCHORS: return "RESET_RETAINING_ANCHORS";
    case M11_TERMINAL_UNSAFE_LAST_CLOSE_OCCURRED: return "UNSAFE_LAST_CLOSE_OCCURRED";
    }
    return "?";
}
