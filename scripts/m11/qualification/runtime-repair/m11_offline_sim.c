#include "m11_offline_sim.h"

#include <errno.h>
#include <string.h>

void m11_sim_default_marble_config(m11_sim_config_t *cfg) {
    if (!cfg) return;
    memset(cfg, 0, sizeof(*cfg));
    cfg->acdb_resolved = true;
    cfg->rx_subgraphs[0] = 0xB0000023u;
    cfg->rx_subgraphs[1] = 0xB0000024u;
    cfg->rx_subgraphs[2] = 0xB0000025u;
    cfg->rx_subgraphs[3] = 0xB0000002u;
    cfg->vi_tx_subgraphs[0] = 0xB00000D5u;
    cfg->vi_tx_subgraphs[1] = 0xB00000CEu;
    cfg->hw_ep_rx_iid = 0x0000428Fu;
    cfg->sp_rx_iid = M11_AW_SP_RX_MODULE_IID; /* 0x42D3 */
    cfg->vi_tx_iid = M11_AW_VI_TX_MODULE_IID; /* 0x42D4 */
    cfg->sample_rate_hz = 96000u;
    cfg->bit_width = 32u;
    cfg->num_channels = 3u;
    cfg->lpaif_type = 2u; /* LPAIF_TERTIARY */
    cfg->enable_vi_tx_graph = true;
    cfg->aw_dev_0_switch = 0; /* Disable */
    cfg->aw_dev_1_switch = 0; /* Disable */
    cfg->amp_enable_requested = false;

    int32_t pair[2] = { M11_MARBLE_CH0_FACTORY_MOHM, M11_MARBLE_CH1_FACTORY_MOHM };
    memcpy(cfg->calr_bytes, pair, sizeof(pair));
    cfg->calr_len = sizeof(pair);
}

static int validate_acdb_contract(const m11_sim_config_t *cfg) {
    if (!cfg->acdb_resolved) return -ENOENT;
    if (cfg->rx_subgraphs[0] != 0xB0000023u ||
        cfg->rx_subgraphs[1] != 0xB0000024u ||
        cfg->rx_subgraphs[2] != 0xB0000025u ||
        cfg->rx_subgraphs[3] != 0xB0000002u) {
        return -ENOENT;
    }
    if (cfg->vi_tx_subgraphs[0] != 0xB00000D5u ||
        cfg->vi_tx_subgraphs[1] != 0xB00000CEu) {
        return -ENOENT;
    }
    if (cfg->hw_ep_rx_iid != 0x0000428Fu ||
        cfg->sp_rx_iid != M11_AW_SP_RX_MODULE_IID ||
        cfg->vi_tx_iid != M11_AW_VI_TX_MODULE_IID) {
        return -EPROTO;
    }
    if (cfg->sample_rate_hz != 96000u || cfg->bit_width != 32u ||
        cfg->num_channels != 3u || cfg->lpaif_type != 2u) {
        return -EINVAL;
    }
    return 0;
}

int m11_sim_run_speaker_qualification(const m11_sim_config_t *cfg,
                                      m11_gpr_engine_t *gpr,
                                      m11_shmem_mgr_t *shmem,
                                      uint32_t timeout_ms,
                                      m11_sim_report_t *out_report) {
    if (!cfg || !gpr || !shmem || !out_report || timeout_ms == 0) return -EINVAL;
    memset(out_report, 0, sizeof(*out_report));
    out_report->final_shmem_state = M11_SHMEM_STATE_NOT_ALLOCATED;
    out_report->simulation_boundary = M11_SIM_BOUNDARY_DESCRIPTION;

    /* Step 0: Fail-closed amplifier switch gate BEFORE touching transport or DSP */
    if (cfg->amp_enable_requested || cfg->aw_dev_0_switch != 0 || cfg->aw_dev_1_switch != 0) {
        out_report->primary_errno = -EACCES;
        return -EACCES;
    }

    /* Step 1: Validate Forte ACDB subgraph & hardware endpoint contract */
    int rc = validate_acdb_contract(cfg);
    if (rc < 0) {
        out_report->primary_errno = rc;
        return rc;
    }

    /* Step 2: Validate factory calibration pair before opening transport */
    m11_aw_cal_pair_t cal;
    rc = m11_aw_parse_calr_pair(cfg->calr_bytes, cfg->calr_len, &cal);
    if (rc < 0) {
        out_report->primary_errno = rc;
        return rc;
    }

    /* Step 3: Open single held-fd GPR session */
    rc = m11_gpr_engine_open(gpr);
    if (rc < 0) {
        out_report->primary_errno = rc;
        return rc;
    }

    m11_shmem_region_t shmem_reg;
    memset(&shmem_reg, 0, sizeof(shmem_reg));
    shmem_reg.state = M11_SHMEM_STATE_NOT_ALLOCATED;
    shmem_reg.dma_buf_fd = -1;

    uint32_t spf_state = 0;
    uint32_t dsp_status = 0;

    bool vi_tx_open_in_flight = false;
    bool vi_tx_start_in_flight = false;
    bool rx_open_in_flight = false;
    bool rx_start_in_flight = false;

    /* Step 4: Query APM_CMD_GET_SPF_STATE (0x01001021 -> 0x02001007) */
    rc = m11_gpr_query_spf_state(gpr, timeout_ms, &spf_state);
    if (rc < 0) goto cleanup;
    out_report->spf_ready = (spf_state == 1u);

    /*
     * Step 5: Allocate DMA-BUF, import into msm_audio_ion (0x40046161), and send
     * APM_CMD_SHARED_MEM_MAP_REGIONS (0x0100100C) with mem_pool_id=3, client_data=1,
     * property_flag=0x4 (OFFSET_MODE), shm_addr_lsw=dma_buf_fd.
     */
    rc = m11_shmem_alloc_and_map(shmem, M11_SHMEM_MODE_DMA_ION_OFFSET, 16416u, false, &shmem_reg);
    if (rc < 0) goto cleanup;
    out_report->shmem_mapped = true;

    /*
     * Step 6: Open & Prepare VI TX feedback subgraph (if enabled) using
     * out-of-band APM_CMD_GRAPH_OPEN (shm_offset = 0) with DMA_BUF_IOCTL_SYNC
     * cache flush (0x3 -> write -> 0x7) and in-band APM_CMD_GRAPH_PREPARE
     * with apm_cmd_header_t + APM_PARAM_ID_SUB_GRAPH_LIST (0x08001005).
     */
    if (cfg->enable_vi_tx_graph) {
        vi_tx_open_in_flight = true;
        rc = m11_apm_transact_graph_open_region(gpr, shmem, &shmem_reg, 0u,
                                                cfg->vi_tx_subgraphs, 2u,
                                                timeout_ms, &dsp_status);
        if (rc < 0) {
            if ((rc == -EREMOTEIO && dsp_status != 0u) ||
                gpr->last_tx_status != M11_GPR_TX_SENT) {
                if (gpr->last_tx_status == M11_GPR_TX_NONE ||
                    gpr->last_tx_status == M11_GPR_TX_NOT_ATTEMPTED ||
                    (rc == -EREMOTEIO && dsp_status != 0u)) {
                    vi_tx_open_in_flight = false;
                }
            }
            goto cleanup;
        }
        out_report->vi_tx_opened = true;

        rc = m11_apm_transact_graph_mgmt(gpr, M11_APM_CMD_GRAPH_PREPARE,
                                         cfg->vi_tx_subgraphs, 2u,
                                         timeout_ms, &dsp_status);
        if (rc < 0) goto cleanup;
        out_report->vi_tx_prepared = true;
    }

    /*
     * Step 7: Open & Prepare Speaker RX subgraph chain using out-of-band
     * APM_CMD_GRAPH_OPEN (shm_offset = 64) with DMA_BUF_IOCTL_SYNC cache flush
     * and in-band APM_CMD_GRAPH_PREPARE.
     */
    rx_open_in_flight = true;
    rc = m11_apm_transact_graph_open_region(gpr, shmem, &shmem_reg, 64u,
                                            cfg->rx_subgraphs, 4u,
                                            timeout_ms, &dsp_status);
    if (rc < 0) {
        if ((rc == -EREMOTEIO && dsp_status != 0u) ||
            gpr->last_tx_status == M11_GPR_TX_NONE ||
            gpr->last_tx_status == M11_GPR_TX_NOT_ATTEMPTED) {
            rx_open_in_flight = false;
        }
        goto cleanup;
    }
    out_report->rx_opened = true;

    rc = m11_apm_transact_graph_mgmt(gpr, M11_APM_CMD_GRAPH_PREPARE,
                                     cfg->rx_subgraphs, 4u,
                                     timeout_ms, &dsp_status);
    if (rc < 0) goto cleanup;
    out_report->rx_prepared = true;

    /*
     * Step 8: Apply & verify Awinic Speaker Protection Re (SET_CFG + GET_CFG readback)
     * addressed to dst_port = 0x42D3 (M11_AW_SP_RX_MODULE_IID).
     */
    {
        m11_aw_safety_context_t sctx = {
            .aw_dev_0_switch = cfg->aw_dev_0_switch,
            .aw_dev_1_switch = cfg->aw_dev_1_switch,
            .amp_enable_requested = cfg->amp_enable_requested,
            .vi_tx_subgraph_opened = out_report->vi_tx_opened,
            .vi_tx_subgraph_prepared = out_report->vi_tx_prepared,
            .vi_tx_module_iid = cfg->vi_tx_iid,
            .sp_rx_module_iid = cfg->sp_rx_iid,
        };
        rc = m11_aw_apply_and_verify_re_dsp_ex(gpr, &sctx, &cal, timeout_ms,
                                               &out_report->aw_report);
        out_report->aw_report_valid = true;
        if (rc < 0) goto cleanup;
        out_report->cal_applied_and_verified = out_report->aw_report.pair_re_readback_verified;
    }

    /*
     * Step 9: Start VI TX feedback graph then RX Speaker graph in simulation only.
     * Physical amplifiers remain strictly disabled (no hardware path exists).
     */
    vi_tx_start_in_flight = true;
    rc = m11_apm_transact_graph_mgmt(gpr, M11_APM_CMD_GRAPH_START,
                                     cfg->vi_tx_subgraphs, 2u,
                                     timeout_ms, &dsp_status);
    if (rc < 0) {
        if (rc == -EREMOTEIO && dsp_status != 0u) vi_tx_start_in_flight = false;
        goto cleanup;
    }
    out_report->vi_tx_started = true;

    rx_start_in_flight = true;
    rc = m11_apm_transact_graph_mgmt(gpr, M11_APM_CMD_GRAPH_START,
                                     cfg->rx_subgraphs, 4u,
                                     timeout_ms, &dsp_status);
    if (rc < 0) {
        if (rc == -EREMOTEIO && dsp_status != 0u) rx_start_in_flight = false;
        goto cleanup;
    }
    out_report->rx_started = true;
    out_report->graphs_started = true;

cleanup:
    out_report->primary_errno = rc;
    int cleanup_err = 0;
    bool all_cleanup_acked = true;

    /*
     * Deterministic reverse-order teardown with strict failure preservation:
     * Any unacknowledged STOP, CLOSE, or UNMAP (or PDR while remote state was active)
     * prevents claiming clean_teardown and records cleanup_errno without erasing primary_errno.
     */
    if (gpr->pdr_down) {
        if (vi_tx_open_in_flight || rx_open_in_flight ||
            vi_tx_start_in_flight || rx_start_in_flight) {
            all_cleanup_acked = false;
            if (cleanup_err == 0) cleanup_err = -ENETRESET;
        }
    } else {
        if (rx_start_in_flight) {
            int crc = m11_apm_transact_graph_mgmt(gpr, M11_APM_CMD_GRAPH_STOP,
                                                  cfg->rx_subgraphs, 4u,
                                                  timeout_ms, &dsp_status);
            if (crc < 0) {
                all_cleanup_acked = false;
                if (cleanup_err == 0) cleanup_err = crc;
            }
        }
        if (vi_tx_start_in_flight) {
            int crc = m11_apm_transact_graph_mgmt(gpr, M11_APM_CMD_GRAPH_STOP,
                                                  cfg->vi_tx_subgraphs, 2u,
                                                  timeout_ms, &dsp_status);
            if (crc < 0) {
                all_cleanup_acked = false;
                if (cleanup_err == 0) cleanup_err = crc;
            }
        }
        if (rx_open_in_flight) {
            int crc = m11_apm_transact_graph_mgmt(gpr, M11_APM_CMD_GRAPH_CLOSE,
                                                  cfg->rx_subgraphs, 4u,
                                                  timeout_ms, &dsp_status);
            if (crc < 0) {
                all_cleanup_acked = false;
                if (cleanup_err == 0) cleanup_err = crc;
            }
        }
        if (vi_tx_open_in_flight) {
            int crc = m11_apm_transact_graph_mgmt(gpr, M11_APM_CMD_GRAPH_CLOSE,
                                                  cfg->vi_tx_subgraphs, 2u,
                                                  timeout_ms, &dsp_status);
            if (crc < 0) {
                all_cleanup_acked = false;
                if (cleanup_err == 0) cleanup_err = crc;
            }
        }
    }

    /*
     * P2: an UNRESOLVED region that still has a correlated MAP/UNMAP outstanding gets one
     * bounded chance to collect its late response before teardown gives up. reconcile() only
     * changes ownership on a response that matches the token and peer; it never infers.
     */
    if (shmem_reg.state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED &&
        shmem_reg.orphan_kind != M11_SHMEM_ORPHAN_NONE) {
        (void)m11_shmem_reconcile(shmem, &shmem_reg, timeout_ms);
    }

    out_report->graph_cleanup_unresolved = !all_cleanup_acked;
    /*
     * Post-MAP hold (CP2 criterion 5): a region whose MAP may have reached the ADSP (write_fn
     * entered, no unsent proof) gets no UNMAP and no local release; it stays held until the
     * retaining reset. Only a region proven never sent may still finish its local release.
     */
    const bool hold = shmem_reg.map_tx_started && !shmem_reg.map_tx_unsent_proof;
    out_report->post_map_hold = hold;
    /* PD down while held: the handle can no longer be trusted. Record UNKNOWN through the
     * region manager (no UNMAP, nothing released); the UNMAP call below is never entered. */
    if (hold && gpr->pdr_down) {
        (void)m11_shmem_note_pd_down(shmem, &shmem_reg);
        all_cleanup_acked = false;
        if (cleanup_err == 0) cleanup_err = -ENETRESET;
    }
    /* A lost OPEN/CLOSE/STOP result leaves possible graph access to the backing.
     * Do not race UNMAP against that access just to reach zero local counters. */
    if (!hold && (all_cleanup_acked || gpr->pdr_down) &&
        shmem_reg.state != M11_SHMEM_STATE_NOT_ALLOCATED &&
        shmem_reg.state != M11_SHMEM_STATE_RELEASED) {
        out_report->unmap_attempted = true;
        int urc = m11_shmem_unmap_and_free(shmem, &shmem_reg);
        if (urc < 0 || shmem_reg.state != M11_SHMEM_STATE_RELEASED) {
            all_cleanup_acked = false;
            if (cleanup_err == 0) cleanup_err = (urc < 0) ? urc : -EBUSY;
        }
    }

    if (shmem_reg.cleanup_error < 0) {
        all_cleanup_acked = false;
        if (cleanup_err == 0) cleanup_err = shmem_reg.cleanup_error;
    }

    const uint32_t orphans_before_close = m11_gpr_engine_orphan_count(gpr);
    bool retains_backing = shmem_reg.state != M11_SHMEM_STATE_NOT_ALLOCATED &&
                           shmem_reg.state != M11_SHMEM_STATE_RELEASED;
    out_report->retained_region_valid = retains_backing;
    if (retains_backing) out_report->retained_region = shmem_reg;
    /* Exact audio_pkt release calls CLOSE_ALL and then global ION crash cleanup
     * even on a CLOSE_ALL failure. Preserve the endpoint and correlation here.
     * A real process can still exit/be killed: hardware runtime remains BLOCKED
     * until an independently qualified custodian/recovery contract exists. */
    out_report->endpoint_close_deferred = retains_backing ||
        out_report->graph_cleanup_unresolved || orphans_before_close != 0u;
    /* The hold defers the close by policy: that alone is not a cleanup failure. */
    const bool hold_only = hold && all_cleanup_acked && cleanup_err == 0 &&
                           shmem_reg.state == M11_SHMEM_STATE_DSP_MAP_ACKNOWLEDGED &&
                           !out_report->graph_cleanup_unresolved && orphans_before_close == 0u;
    if (!out_report->endpoint_close_deferred) {
        int close_rc = m11_gpr_engine_close(gpr);
        if (close_rc < 0) {
            all_cleanup_acked = false;
            if (cleanup_err == 0) cleanup_err = close_rc;
        }
    } else if (!hold_only) {
        all_cleanup_acked = false;
        if (cleanup_err == 0) cleanup_err = -EBUSY;
    }

    out_report->orphans_outstanding = orphans_before_close;
    out_report->cleanup_errno = cleanup_err;
    out_report->final_shmem_state = shmem_reg.state;
    out_report->shmem_cause = shmem_reg.cause;
    out_report->shmem_blocker = shmem_reg.blocker;
    out_report->local_release_pending = shmem->local_release_pending_regions;
    out_report->gpr_open_count = gpr->open_count;
    out_report->gpr_close_count = gpr->close_count;
    out_report->unresolved_ownership = shmem->unresolved_regions;
    out_report->leaked_resources = shmem->active_dma_fds + shmem->active_mmaps +
                                   shmem->active_ion_imports + shmem->active_dsp_maps +
                                   shmem->unresolved_regions +
                                   (gpr->is_open ? 1u : 0u);
    out_report->clean_teardown = (all_cleanup_acked &&
                                  cleanup_err == 0 &&
                                  out_report->leaked_resources == 0u &&
                                  out_report->unresolved_ownership == 0u &&
                                  out_report->gpr_open_count == 1u &&
                                  out_report->gpr_close_count == 1u);
    /* Exactly the held region remains: mapped, imported, CPU-mapped, its fd and the endpoint. */
    out_report->retaining_teardown = (hold_only && all_cleanup_acked && cleanup_err == 0 &&
                                      out_report->unresolved_ownership == 0u &&
                                      out_report->local_release_pending == 0u &&
                                      shmem->active_dma_fds == 1u && shmem->active_mmaps == 1u &&
                                      shmem->active_ion_imports == 1u && shmem->active_dsp_maps == 1u &&
                                      gpr->is_open && out_report->gpr_open_count == 1u &&
                                      out_report->gpr_close_count == 0u);

    /*
     * Preserve primary failure semantics: a later cleanup success never erases an
     * earlier primary failure, and a cleanup failure on a primary-success run
     * causes the overall transaction to fail rather than returning 0.
     */
    if (rc < 0) return rc;
    if (cleanup_err < 0) return cleanup_err;
    if (!out_report->clean_teardown && !out_report->retaining_teardown) return -EIO;
    return 0;
}
