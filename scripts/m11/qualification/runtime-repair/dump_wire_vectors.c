/*
 * Prints the bytes the production packers emit, one `name hex` line per vector, so an
 * INDEPENDENT Python builder (test_runtime_repair_py.py) can rebuild each packet from the
 * documented layout and compare. Offline; no I/O besides stdout.
 */
#include <stdio.h>
#include <string.h>

#include "m11_apm_protocol.h"
#include "m11_aw_protection.h"
#include "m11_gpr_engine.h"
#include "m11_shmem.h"

static void emit(const char *name, const uint8_t *b, size_t n) {
    printf("%s ", name);
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

#define PACK_OK(call) do { if ((call) != 0) { fprintf(stderr, "packer failed: %s\n", #call); return 1; } } while (0)

int main(void) {
    uint8_t buf[512];
    size_t n = 0;

    PACK_OK(m11_gpr_pack_packet(buf, sizeof buf, &n, 1u, 0x2001u, 0x11223344u, M11_APM_CMD_GET_SPF_STATE, NULL, 0u));
    emit("get_spf_state", buf, n);

    PACK_OK(m11_shmem_pack_map_regions_pkt(buf, sizeof buf, &n, 0x2002u, 1u, 100, 20480u));
    emit("map_regions", buf, n);

    PACK_OK(m11_shmem_pack_unmap_regions_pkt(buf, sizeof buf, &n, 0x2002u, 2u, 0xA0001234u));
    emit("unmap_regions", buf, n);

    PACK_OK(m11_aw_pack_set_cfg_pkt(buf, sizeof buf, &n, 0x2001u, 3u, 0u, 6372));
    emit("set_cfg_ch0_6372", buf, n);
    PACK_OK(m11_aw_pack_set_cfg_pkt(buf, sizeof buf, &n, 0x2001u, 4u, 1u, 7001));
    emit("set_cfg_ch1_7001", buf, n);
    PACK_OK(m11_aw_pack_get_cfg_pkt(buf, sizeof buf, &n, 0x2001u, 5u, 1u));
    emit("get_cfg_ch1", buf, n);
    PACK_OK(m11_aw_pack_get_cfg_rsp_pkt(buf, sizeof buf, &n, 0x2001u, 5u, 0u, 1u, 7001));
    emit("get_cfg_rsp_ch1_7001", buf, n);

    const uint32_t vi[2] = { 0xB00000D5u, 0xB00000CEu };
    const uint32_t rx[4] = { 0xB0000023u, 0xB0000024u, 0xB0000025u, 0xB0000002u };
    PACK_OK(m11_apm_pack_graph_mgmt_cmd(buf, sizeof buf, &n, 0x2001u, 5u, 0x01001001u, vi, 2u));
    emit("graph_prepare_vi", buf, n);
    PACK_OK(m11_apm_pack_graph_mgmt_cmd(buf, sizeof buf, &n, 0x2001u, 6u, 0x01001002u, rx, 4u));
    emit("graph_start_rx", buf, n);

    /* Out-of-band GRAPH_OPEN: 16-byte apm_cmd_header_t, then the block written into shared memory. */
    uint8_t shm[4096];
    memset(shm, 0xEE, sizeof shm);
    m11_apm_cmd_header_t hdr;
    size_t written = 0;
    PACK_OK(m11_apm_build_graph_open_oob(shm, sizeof shm, 64u, 0xA0001234u, rx, 4u, &hdr, &written));
    emit("graph_open_cmd_hdr", (const uint8_t *)&hdr, sizeof hdr);
    emit("graph_open_shm_block_at_64", shm + 64, written);
    printf("graph_open_shm_written %zu\n", written);
    int untouched = 1;
    for (size_t i = 0; i < 64u; i++) if (shm[i] != 0xEE) untouched = 0;
    for (size_t i = 64u + written; i < sizeof shm; i++) if (shm[i] != 0xEE) untouched = 0;
    printf("graph_open_outside_block_untouched %d\n", untouched);
    return 0;
}
