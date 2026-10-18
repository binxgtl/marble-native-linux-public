/* The composed native custodian runner core — see custodian_runner_native.h. */
#define _GNU_SOURCE
#include "custodian_runner_native.h"
#include "heap_node_native.h"
#include <errno.h>
#include <string.h>
#include <unistd.h>

#define FAIL(n, rc) do { if (step) *step = (n); return (rc); } while (0)

int m11_crunner_census(m11_crunner *r) {
    if (!r || !r->started) return -1;
    int ok = r->cfg.endpoint->state == M11_ANCHOR_HELD && m11_anchor_check(r->cfg.endpoint) == 0 &&
             r->cfg.ion->state == M11_ANCHOR_HELD && m11_anchor_check(r->cfg.ion) == 0 &&
             m11_heap_census_pid(getpid(), r->cfg.heap_rdev, -1) == 0 &&
             m11_dmabuf_census_pid(&r->pool, getpid(), 1) == 0;
    if (!ok) r->census_failed = 1; /* latched for the boot */
    return ok ? 0 : -1;
}

int m11_crunner_start(m11_crunner *r, const m11_crunner_config *cfg, uint64_t now_ms, int *step) {
    if (step) *step = 0;
    if (!r || !cfg || !cfg->endpoint || !cfg->ion || cfg->heap_fd < 0 || !cfg->pd || !cfg->journal ||
        !cfg->cmdline || !cfg->boot_epoch || !cfg->timeout_ms || !cfg->recovery_budget_ms ||
        !cfg->endpoint->ops.close_pair || !cfg->ion->ops.close_pair) return -EINVAL; /* sealed pairs only */
    memset(r, 0, sizeof *r);
    r->cfg = *cfg;

    /* 1. the effective cmdline gate */
    m11_custodian_model_contract ct = {.exclusive_importer = true, .no_other_endpoint = true,
        .no_pcm_clients = true, .strict_iommu = m11_custodian_cmdline_allowed(cfg->cmdline),
        .graph_quiescent = true, .nack_atomicity_model = true, .final_anchor_pid1 = true};
    if (!ct.strict_iommu) FAIL(1, -EPERM);
    /* 2. the PD must be UP */
    if (cfg->pd->pump_fn(cfg->pd->user, now_ms) != 1) FAIL(2, -ENETRESET);
    /* 3. pool from the heap, heap closed, pool sealed over the owner pairs */
    int rc = m11_dmabuf_pool_build(&r->pool, cfg->heap_fd, cfg->pool_count, cfg->pool_len, cfg->pool_base, cfg->sys);
    if (rc) FAIL(3, rc);
    if (close(cfg->heap_fd)) FAIL(3, -EIO); /* nothing allocates after the pool */
    r->cfg.heap_fd = -1;
    const int base[2] = {cfg->endpoint->anchor_fd, cfg->ion->anchor_fd};
    if ((rc = m11_dmabuf_pool_seal(&r->pool, base, 2))) FAIL(3, rc);
    /* 4. ledger, transport (anchor + PD monitor) wrapped by the journal, engine */
    if ((rc = m11_model_new_boot(&r->boot, cfg->boot_epoch, now_ms))) FAIL(4, rc);
    if ((rc = m11_gpr_native_transport_pd(&r->link, cfg->endpoint, cfg->pd, &r->inner))) FAIL(4, rc);
    if ((rc = m11_intent_transport(&r->journal, &r->inner, cfg->journal, &r->boot, &r->transport))) FAIL(4, rc);
    if ((rc = m11_gpr_engine_init(&r->eng, &r->transport, cfg->src_port ? cfg->src_port : 0x0100u)) ||
        (rc = m11_gpr_engine_open(&r->eng))) FAIL(4, rc);
    /* 5. pooled backend over the ION anchor, manager, custodian, PDR loop */
    if ((rc = m11_shmem_native_backend_pool(&r->shm, cfg->ion, &r->pool, cfg->sys, &r->backend))) FAIL(5, rc);
    if ((rc = m11_shmem_mgr_init(&r->mgr, &r->backend, &r->eng, cfg->timeout_ms))) FAIL(5, rc);
    if ((rc = m11_custodian_init(&r->cust, &r->boot, &r->mgr, &ct, cfg->recovery_budget_ms))) FAIL(5, rc);
    if ((rc = m11_pdr_loop_init(&r->loop, &r->cust, &r->link))) FAIL(5, rc);
    r->term = (m11_terminal_native){.c = &r->cust, .anchors = {cfg->endpoint, cfg->ion}, .nanchors = 2,
                                    .pool = &r->pool, .sink = cfg->journal, .ops = cfg->terminal_ops};
    /* 6. the composed census */
    r->started = 1;
    if (m11_crunner_census(r)) FAIL(6, -EOWNERDEAD);
    return 0;
}

/* Every custodian call: census before (latched refusal), the call, PDR settle, census after. */
int m11_crunner_map(m11_crunner *r, size_t bytes, uint64_t now_ms, unsigned *slot) {
    if (!r || !r->started || !slot) return -EINVAL;
    *slot = (unsigned)-1;
    if (r->census_failed || m11_crunner_census(r)) return -EOWNERDEAD; /* census before MAP */
    int rc = m11_custodian_map(&r->cust, bytes, now_ms, slot);
    (void)m11_pdr_loop_settle(&r->loop, now_ms); /* settle after MAP */
    if (m11_crunner_census(r) && !rc) rc = -EOWNERDEAD;
    return rc;
}
int m11_crunner_retire(m11_crunner *r, unsigned slot, uint64_t now_ms) {
    if (!r || !r->started) return -EINVAL;
    if (r->census_failed || m11_crunner_census(r)) return -EOWNERDEAD; /* census before UNMAP */
    int rc = m11_custodian_retire(&r->cust, slot, now_ms);
    (void)m11_pdr_loop_settle(&r->loop, now_ms); /* settle after UNMAP */
    if (m11_crunner_census(r) && !rc) rc = -EOWNERDEAD;
    return rc;
}
int m11_crunner_idle(m11_crunner *r, uint32_t budget_ms, uint64_t now_ms) {
    if (!r || !r->started) return -EINVAL;
    int rc = m11_pdr_loop_idle(&r->loop, budget_ms, now_ms);
    (void)m11_crunner_census(r);
    return rc;
}
int m11_crunner_close(m11_crunner *r) {
    if (!r || !r->started) return -EINVAL;
    int rc = m11_custodian_close(&r->cust);
    (void)m11_pdr_loop_settle(&r->loop, r->boot.last_ms);
    return rc;
}
m11_terminal_action m11_crunner_action(m11_crunner *r, uint64_t now_ms) {
    if (!r || !r->started) return M11_TERMINAL_RESET_RETAINING_ANCHORS;
    return m11_pdr_loop_settle(&r->loop, now_ms);
}
int m11_crunner_end(m11_crunner *r, uint64_t now_ms) {
    if (!r || !r->started) return -EINVAL;
    (void)m11_pdr_loop_settle(&r->loop, now_ms);
    return m11_terminal_native_end(&r->term, now_ms);
}
