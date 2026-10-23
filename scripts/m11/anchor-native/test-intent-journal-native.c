/* G7 stand-in test: the intent journal wrapped around the G2 transport, under the REAL custodian,
 * region manager and engine, with the G3 backend over fixture syscalls. The journal sink is a pipe
 * the forked peer (the ADSP stand-in) reads: on every packet it requires that packet's record to be
 * already there, so the ordering journal-before-TX is checked by another process. No device. */
#ifndef M11_CUSTODIAN_NATIVE
#error "test-intent-journal-native.c builds only with M11_CUSTODIAN_NATIVE"
#endif
#define _GNU_SOURCE
#include "intent_journal_native.h"
#include "gpr_transport_native.h"
#include "shmem_backend_native.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* ---- fixture syscalls ---- */
static int fx_heap = -1, fx_ion = -1;
static int fx_ioctl(int fd, unsigned long req, void *arg) {
    if (req == M11_DMA_HEAP_IOCTL_ALLOC) {
        m11_dma_heap_allocation_data *d = arg;
        assert(fd == fx_heap);
        int m = memfd_create("m11-g7", MFD_CLOEXEC);
        assert(m >= 0 && ftruncate(m, (off_t)d->len) == 0);
        d->fd = (uint32_t)m;
        return 0;
    }
    if (req == M11_DMA_BUF_IOCTL_SYNC) return 0;
    if (req == M11_MSM_AUDIO_ION_MAP_PHYS || req == M11_MSM_AUDIO_ION_UNMAP) { assert(fd == fx_ion); return 0; }
    errno = ENOTTY; return -1;
}
static int fx_munmap(void *a, size_t l) { return munmap(a, l); }
static const m11_shmem_native_sys fx_sys = {fx_ioctl, mmap, fx_munmap, close};

/* ---- the peer: verifies the journal record precedes each packet, then answers ---- */
static void reply(int ep, const m11_gpr_hdr_t *h, uint32_t opcode, const void *pl, size_t n) {
    uint8_t tx[64]; size_t txl = 0;
    if (m11_gpr_pack_packet_ex(tx, sizeof tx, &txl, M11_GPR_DOMAIN_APPS, M11_GPR_DOMAIN_ADSP, 0,
                               h->src_port, h->dst_port, h->token, opcode, pl, n) < 0) _exit(104);
    (void)send(ep, tx, txl, 0);
}
static void peer(int ep, int journal) {
    alarm(10);
    static char seen[16384]; size_t have = 0;
    int got = 0;
    for (;;) {
        uint8_t rx[M11_GPR_MAX_PKT_BYTES];
        ssize_t n = recv(ep, rx, sizeof rx, 0);
        if (n <= 0) _exit(got);
        got++;
        m11_gpr_hdr_t h; const uint8_t *pl; size_t pll;
        if (m11_gpr_validate_packet(rx, (size_t)n, &h, &pl, &pll) < 0) _exit(100);
        for (;;) { /* everything journaled so far */
            ssize_t r = read(journal, seen + have, sizeof seen - 1 - have);
            if (r <= 0) break;
            have += (size_t)r;
        }
        seen[have] = 0;
        char want[48]; snprintf(want, sizeof want, "op=%08x tok=%08x", h.opcode, h.token);
        if (!strstr(seen, want)) _exit(110); /* a packet arrived before its journal record */
        if (h.opcode == M11_APM_CMD_SHARED_MEM_MAP_REGIONS) {
            m11_apm_rsp_shared_mem_map_t r = {.mem_map_handle = 0xA0000001u};
            reply(ep, &h, M11_APM_CMDRSP_SHARED_MEM_MAP_REGIONS, &r, sizeof r);
        } else if (h.opcode == M11_APM_CMD_GET_SPF_STATE) {
            uint32_t ready = 1;
            reply(ep, &h, M11_APM_CMD_RSP_GET_SPF_STATE, &ready, sizeof ready);
        } else {
            m11_gpr_ibasic_rsp_t r = {.cmd_opcode = h.opcode, .status = 0};
            reply(ep, &h, M11_GPR_IBASIC_RSP_RESULT, &r, sizeof r);
        }
    }
}

/* ---- the test sink: the production fd sink to the peer's pipe, plus a copy here ---- */
static char jr[8][M11_INTENT_RECORD_MAX]; static unsigned jcount; static int sink_fail;
static m11_intent_fd_sink fds; static m11_intent_sink fd_sink;
static int tee_append(void *user, const char *rec, size_t len) {
    (void)user;
    if (sink_fail) return -EIO;
    int rc = fd_sink.append_fn(fd_sink.user, rec, len);
    if (!rc && jcount < 8 && len < M11_INTENT_RECORD_MAX) { memcpy(jr[jcount], rec, len); jr[jcount][len] = 0; jcount++; }
    return rc;
}
static const m11_intent_sink jsink = {tee_append, NULL};

static uint64_t ms(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u;
}
struct rig {
    int sv[2], jp[2]; pid_t pid;
    m11_pid1_anchor ep, ion; m11_gpr_native_link glink; m11_gpr_transport_t inner, t; m11_intent_link ilink;
    m11_gpr_engine_t eng; m11_shmem_native_link slink; m11_shmem_backend_t b; m11_shmem_mgr_t mgr;
    m11_boot_ledger boot; m11_custodian cust;
};
static void start(struct rig *r) {
    memset(r, 0, sizeof *r);
    jcount = 0; sink_fail = 0;
    if (fx_heap < 0) fx_heap = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (fx_ion < 0) fx_ion = open("/dev/null", O_RDWR | O_CLOEXEC);
    assert(fx_heap >= 0 && fx_ion >= 0);
    assert(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, r->sv) == 0);
    assert(pipe2(r->jp, O_CLOEXEC) == 0);
    r->pid = fork(); assert(r->pid >= 0);
    if (r->pid == 0) {
        close(r->sv[0]); close(r->jp[1]);
        if (fcntl(r->jp[0], F_SETFL, O_NONBLOCK)) _exit(120);
        peer(r->sv[1], r->jp[0]);
    }
    close(r->sv[1]); close(r->jp[0]);
    assert(m11_intent_sink_fd(&fds, r->jp[1], &fd_sink) == 0);
    r->ep.state = M11_ANCHOR_HELD; r->ep.anchor_fd = r->sv[0]; r->ep.owner_pid = getpid();
    r->ion.state = M11_ANCHOR_HELD; r->ion.anchor_fd = fx_ion; r->ion.owner_pid = getpid();
    assert(m11_model_new_boot(&r->boot, 7, ms()) == 0);
    assert(m11_gpr_native_transport(&r->glink, &r->ep, &r->inner) == 0);
    assert(m11_intent_transport(&r->ilink, &r->inner, &jsink, &r->boot, &r->t) == 0);
    assert(m11_gpr_engine_init(&r->eng, &r->t, 0x0100u) == 0 && m11_gpr_engine_open(&r->eng) == 0);
    assert(m11_shmem_native_backend(&r->slink, &r->ion, fx_heap, &fx_sys, &r->b) == 0);
    assert(m11_shmem_mgr_init(&r->mgr, &r->b, &r->eng, 300) == 0);
    const m11_custodian_model_contract ct = {true, true, true, true, true, true, true};
    assert(m11_custodian_init(&r->cust, &r->boot, &r->mgr, &ct, 2000) == 0);
}
static int stop(struct rig *r) {
    close(r->sv[0]); close(r->jp[1]);
    int st; assert(waitpid(r->pid, &st, 0) == r->pid && WIFEXITED(st));
    return WEXITSTATUS(st);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGPIPE, SIG_IGN);
    struct rig r; unsigned slot; int rc; uint32_t tok;

    /* 1. the record format */
    uint8_t pkt[64]; size_t pl = 0; char rec[M11_INTENT_RECORD_MAX];
    assert(m11_shmem_pack_map_regions_pkt(pkt, sizeof pkt, &pl, 0x0100u, 0x2a, 9, 8192) == 0);
    int n = m11_intent_format(rec, sizeof rec, 7, 3, pkt, pl);
    static const char head[] = "<6>M11INTENT v=1 boot=7 seq=3 op=0100100c tok=0000002a cd=1 ";
    assert(n > 0 && rec[n - 1] == '\n' && !strncmp(rec, head, sizeof head - 1));
    assert(strstr(rec, " fd=9 msw=0 bytes=8192 pool=3 regions=1 flags=4\n"));
    assert(m11_intent_format(rec, 40, 7, 3, pkt, pl) == -ENOSPC);
    assert(m11_intent_format(rec, sizeof rec, 7, 3, pkt, 10) == -EBADMSG);
    assert(m11_gpr_pack_packet(pkt, sizeof pkt, &pl, M11_APM_MODULE_IID, 0x0100u, 0x2b, M11_APM_CMD_CLOSE_ALL, NULL, 0) == 0);
    assert(m11_intent_format(rec, sizeof rec, 7, 3, pkt, pl) == -EPERM);
    /* CP2 post-MAP hold: the UNMAP opcode is outside the set too (no record, so never a TX). */
    assert(m11_shmem_pack_unmap_regions_pkt(pkt, sizeof pkt, &pl, 0x0100u, 0x2c, 0xA0000001u) == 0);
    int un = m11_intent_format(rec, sizeof rec, 7, 3, pkt, pl);
    assert(un == -EPERM);
    printf("PASS record format: MAP fields (fd, size, pool, flags), kmsg level, size and malformed checks, CLOSE_ALL and UNMAP outside the set\n");

    /* 2. the production fd sink */
    int p[2]; m11_intent_fd_sink s; m11_intent_sink sk;
    assert(pipe(p) == 0 && m11_intent_sink_fd(&s, p[1], &sk) == 0);
    assert(sk.append_fn(sk.user, "abc\n", 4) == 0 && s.writes == 1);
    char b4[4]; assert(read(p[0], b4, 4) == 4 && !memcmp(b4, "abc\n", 4));
    close(p[0]);
    assert(sk.append_fn(sk.user, "abc\n", 4) == -EIO && s.writes == 1); /* no reader: EPIPE */
    close(p[1]);
    printf("PASS fd sink: one write(2) per record; a failed write is -EIO\n");

    /* 3. MAP through the custodian, journaled before TX (checked by the peer); then the post-MAP hold:
     *    retire is refused at the custodian, so there is no UNMAP record and no second packet, and
     *    the region keeps its import, mapping and dma-buf fd. */
    start(&r);
    assert(m11_custodian_map(&r.cust, 4096, ms(), &slot) == 0);
    char want[96];
    snprintf(want, sizeof want, " fd=%d msw=0 bytes=4096 pool=3 regions=1 flags=4\n", r.cust.regions[slot].dma_buf_fd);
    assert(jcount == 1 && strstr(jr[0], "boot=7 seq=1 op=0100100c ") && strstr(jr[0], " cd=1 ") && strstr(jr[0], want));
    assert(m11_custodian_retire(&r.cust, slot, ms()) == -EPERM);
    assert(jcount == 1 && r.ilink.journaled == 1 && r.glink.writes == 1 && r.ilink.refused == 0);
    assert(r.cust.occupied[slot] && r.cust.regions[slot].state == M11_SHMEM_STATE_DSP_MAP_ACKNOWLEDGED &&
           r.cust.regions[slot].ion_imported && r.cust.regions[slot].vaddr && r.cust.regions[slot].dma_buf_fd >= 0);
    assert(m11_custodian_terminal_action(&r.cust) == M11_TERMINAL_RESET_RETAINING_ANCHORS);
    assert(stop(&r) == 1);
    printf("PASS MAP journaled before TX (the peer saw its record before the packet), with fd and size; retire refused after the MAP: no UNMAP record, no TX, region held, retaining end\n");

    /* 4. the sink fails: nothing transmitted, and the engine records an unknown TX (fail closed). */
    start(&r);
    sink_fail = 1;
    rc = m11_custodian_map(&r.cust, 4096, ms(), &slot);
    assert(rc < 0 && r.glink.writes == 0 && r.ilink.sink_failures == 1);
    assert(r.cust.regions[slot].state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED &&
           r.cust.regions[slot].cause == M11_SHMEM_CAUSE_MAP_WRITE_ERROR);
    /* the MAP intent was recorded, so the only end is the retaining reset (post-MAP hold) */
    assert(jcount == 0 && m11_custodian_terminal_action(&r.cust) == M11_TERMINAL_RESET_RETAINING_ANCHORS);
    assert(stop(&r) == 0);
    printf("PASS sink failure: no TX; the region stays unresolved (unknown TX, fail closed)\n");

    /* 5. ledger intent first: a MAP the ledger has not recorded is never sent; an UNMAP is never sent. */
    start(&r);
    m11_apm_cmd_shared_mem_map_regions_t cmd = {.mem_pool_id = 3, .num_regions = 1, .property_flag = 4,
                                               .shm_addr_lsw = 5, .mem_size_bytes = 4096};
    rc = m11_gpr_engine_submit_ex(&r.eng, M11_GPR_CLIENT_DATA_SHMEM_OFFSET_MODE, M11_APM_MODULE_IID,
                                  M11_APM_CMD_SHARED_MEM_MAP_REGIONS, &cmd, sizeof cmd, &tok);
    assert(rc < 0 && r.glink.writes == 0 && r.ilink.refused == 1);
    m11_apm_cmd_shared_mem_unmap_regions_t ucmd = {.mem_map_handle = 0xA0000001u};
    rc = m11_gpr_engine_submit_ex(&r.eng, 0, M11_APM_MODULE_IID, M11_APM_CMD_SHARED_MEM_UNMAP_REGIONS, &ucmd, sizeof ucmd, &tok);
    assert(rc < 0 && r.glink.writes == 0 && r.ilink.refused == 2 && jcount == 0);
    r.boot.dsp_unmap_attempted = true; /* even with the ledger's UNMAP intent, an UNMAP never leaves */
    rc = m11_gpr_engine_submit_ex(&r.eng, 0, M11_APM_MODULE_IID, M11_APM_CMD_SHARED_MEM_UNMAP_REGIONS, &ucmd, sizeof ucmd, &tok);
    int unmap_wire = rc < 0 && r.glink.writes == 0 && r.ilink.refused == 3 && jcount == 0;
    assert(unmap_wire);
    assert(stop(&r) == 0);
    printf("PASS ledger first: a MAP without the ledger's intent is refused before the journal and TX; an UNMAP is refused even with the intent recorded\n");

    /* 6. the opcode set: GET_SPF_STATE passes; CLOSE_ALL and unknown opcodes never leave. */
    start(&r);
    uint32_t state = 0;
    assert(m11_gpr_query_spf_state(&r.eng, 2000, &state) == 0 && state == 1 && r.glink.writes == 1 && jcount == 1);
    rc = m11_gpr_engine_submit_ex(&r.eng, 0, M11_APM_MODULE_IID, M11_APM_CMD_CLOSE_ALL, NULL, 0, &tok);
    assert(rc < 0 && r.glink.writes == 1 && jcount == 1);
    rc = m11_gpr_engine_submit_ex(&r.eng, 0, M11_APM_MODULE_IID, 0x01001099u, NULL, 0, &tok);
    assert(rc < 0 && r.glink.writes == 1 && r.ilink.refused == 2);
    assert(stop(&r) == 1);
    printf("PASS opcode set: GET_SPF_STATE journaled and sent; CLOSE_ALL and an unknown opcode refused\n");

    m11_intent_link il; m11_gpr_transport_t out;
    assert(m11_intent_transport(&il, NULL, &jsink, &r.boot, &out) == -EINVAL);
    printf("PASS G7 intent journal (real custodian, manager and engine; G2 transport; cross-process ordering)\n");
    return 0;
}
