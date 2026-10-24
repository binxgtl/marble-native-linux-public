/* G6 stand-in test: the REAL custodian, region manager and engine over the G6 transport (endpoint
 * stand-in: SOCK_SEQPACKET; PD monitor stand-in: a pipe the peer writes 'U' / 'D' to, or closes)
 * and the G3 backend over fixture syscalls. A forked peer plays the ADSP and the PD notifier. No
 * device, driver, QRTR or kernel module. */
#ifndef M11_CUSTODIAN_NATIVE
#error "test-pdr-loop-native.c builds only with M11_CUSTODIAN_NATIVE"
#endif
#define _GNU_SOURCE
#include "pdr_loop_native.h"
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

/* ---- fixture syscalls (memfd dma-bufs, recorded ION fd list) ---- */
static int fx_heap = -1, fx_ion = -1, fx_imported[1024];
static int fx_ioctl(int fd, unsigned long req, void *arg) {
    if (req == M11_DMA_HEAP_IOCTL_ALLOC) {
        m11_dma_heap_allocation_data *d = arg;
        assert(fd == fx_heap);
        int m = memfd_create("m11-g6", MFD_CLOEXEC);
        assert(m >= 0 && m < 1024 && ftruncate(m, (off_t)d->len) == 0);
        d->fd = (uint32_t)m;
        return 0;
    }
    if (req == M11_DMA_BUF_IOCTL_SYNC) return 0;
    if (req == M11_MSM_AUDIO_ION_MAP_PHYS || req == M11_MSM_AUDIO_ION_UNMAP) {
        int v = (int)(uintptr_t)arg;
        assert(fd == fx_ion && v >= 0 && v < 1024);
        fx_imported[v] = req == M11_MSM_AUDIO_ION_MAP_PHYS;
        return 0;
    }
    errno = ENOTTY; return -1;
}
static int fx_munmap(void *a, size_t l) { return munmap(a, l); }
static const m11_shmem_native_sys fx_sys = {fx_ioctl, mmap, fx_munmap, close};

/* ---- the peer: ADSP on the endpoint, PD notifier on the monitor pipe ---- */
enum mode { ANSWER, DOWN_ON_MAP, DOWN_ON_UNMAP, DOWN_THEN_ACK, DOWN_IDLE, HANGUP_IDLE };
static void reply(int ep, const m11_gpr_hdr_t *h, uint32_t opcode, const void *pl, size_t n) {
    uint8_t tx[64]; size_t txl = 0;
    if (m11_gpr_pack_packet_ex(tx, sizeof tx, &txl, M11_GPR_DOMAIN_APPS, M11_GPR_DOMAIN_ADSP, 0,
                               h->src_port, h->dst_port, h->token, opcode, pl, n) < 0 ||
        send(ep, tx, txl, 0) != (ssize_t)txl) _exit(104);
}
static void peer(int ep, int mon, enum mode m) {
    alarm(10);
    int got = 0;
    if (m == DOWN_IDLE || m == HANGUP_IDLE) {
        usleep(100 * 1000);
        if (m == DOWN_IDLE) { if (write(mon, "D", 1) != 1) _exit(105); }
        else close(mon);
    }
    for (;;) {
        uint8_t rx[M11_GPR_MAX_PKT_BYTES];
        ssize_t n = recv(ep, rx, sizeof rx, 0);
        if (n <= 0) _exit(got);
        got++;
        m11_gpr_hdr_t h; const uint8_t *pl; size_t pll;
        if (m11_gpr_validate_packet(rx, (size_t)n, &h, &pl, &pll) < 0) _exit(100);
        if (h.opcode == M11_APM_CMD_SHARED_MEM_MAP_REGIONS) {
            if (m == DOWN_ON_MAP) { if (write(mon, "D", 1) != 1) _exit(105); continue; }
            m11_apm_rsp_shared_mem_map_t r = {.mem_map_handle = 0xA0000001u};
            if (m == DOWN_THEN_ACK) {
                if (write(mon, "D", 1) != 1) _exit(105);
                /* the late ACK: the test may already have stopped listening (endpoint closed) */
                uint8_t tx[64]; size_t txl = 0;
                if (m11_gpr_pack_packet_ex(tx, sizeof tx, &txl, M11_GPR_DOMAIN_APPS, M11_GPR_DOMAIN_ADSP, 0,
                                           h.src_port, h.dst_port, h.token,
                                           M11_APM_CMDRSP_SHARED_MEM_MAP_REGIONS, &r, sizeof r) < 0) _exit(104);
                (void)send(ep, tx, txl, 0);
                continue;
            }
            if (write(mon, "U", 1) != 1) _exit(105); /* PD traffic that stays UP */
            reply(ep, &h, M11_APM_CMDRSP_SHARED_MEM_MAP_REGIONS, &r, sizeof r);
        } else if (h.opcode == M11_APM_CMD_SHARED_MEM_UNMAP_REGIONS) {
            if (m == DOWN_ON_UNMAP) { if (write(mon, "D", 1) != 1) _exit(105); continue; }
            if (write(mon, "U", 1) != 1) _exit(105);
            m11_gpr_ibasic_rsp_t r = {.cmd_opcode = h.opcode, .status = 0};
            reply(ep, &h, M11_GPR_IBASIC_RSP_RESULT, &r, sizeof r);
        }
    }
}

/* ---- PD monitor stand-in: any 'D' or EOF is not UP ---- */
static int pump(void *user, uint64_t now) {
    (void)now;
    int fd = *(int *)user;
    for (;;) {
        char b[16];
        ssize_t n = read(fd, b, sizeof b);
        if (n < 0) return errno == EAGAIN ? 1 : 0;
        if (n == 0) return 0;
        if (memchr(b, 'D', (size_t)n)) return 0;
    }
}

static uint64_t ms(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u;
}
struct rig {
    int sv[2], mp[2]; pid_t pid;
    m11_pid1_anchor ep, ion; m11_pd_monitor mon; m11_gpr_native_link glink; m11_gpr_transport_t t;
    m11_gpr_engine_t eng; m11_shmem_native_link slink; m11_shmem_backend_t b; m11_shmem_mgr_t mgr;
    m11_boot_ledger boot; m11_custodian cust; m11_pdr_loop loop;
};
static void start(struct rig *r, enum mode m) {
    memset(r, 0, sizeof *r);
    memset(fx_imported, 0, sizeof fx_imported);
    if (fx_heap < 0) fx_heap = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (fx_ion < 0) fx_ion = open("/dev/null", O_RDWR | O_CLOEXEC);
    assert(fx_heap >= 0 && fx_ion >= 0);
    assert(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, r->sv) == 0);
    assert(pipe2(r->mp, O_CLOEXEC) == 0);
    r->pid = fork(); assert(r->pid >= 0);
    if (r->pid == 0) { close(r->sv[0]); close(r->mp[0]); peer(r->sv[1], r->mp[1], m); }
    close(r->sv[1]); close(r->mp[1]);
    assert(fcntl(r->mp[0], F_SETFL, O_NONBLOCK) == 0);
    r->ep.state = M11_ANCHOR_HELD; r->ep.anchor_fd = r->sv[0]; r->ep.owner_pid = getpid();
    r->ion.state = M11_ANCHOR_HELD; r->ion.anchor_fd = fx_ion; r->ion.owner_pid = getpid();
    r->mon = (m11_pd_monitor){.fd = r->mp[0], .pump_fn = pump, .user = &r->mp[0]};
    assert(m11_gpr_native_transport_pd(&r->glink, &r->ep, &r->mon, &r->t) == 0);
    assert(m11_gpr_engine_init(&r->eng, &r->t, 0x0100u) == 0 && m11_gpr_engine_open(&r->eng) == 0);
    assert(m11_shmem_native_backend(&r->slink, &r->ion, fx_heap, &fx_sys, &r->b) == 0);
    assert(m11_shmem_mgr_init(&r->mgr, &r->b, &r->eng, 300) == 0);
    assert(m11_model_new_boot(&r->boot, 1, ms()) == 0);
    const m11_custodian_model_contract ct = {true, true, true, true, true, true, true};
    assert(m11_custodian_init(&r->cust, &r->boot, &r->mgr, &ct, 2000) == 0);
    assert(m11_pdr_loop_init(&r->loop, &r->cust, &r->glink) == 0);
}
static int stop(struct rig *r) { /* the peer's packet count */
    close(r->sv[0]); close(r->mp[0]);
    int st; assert(waitpid(r->pid, &st, 0) == r->pid && WIFEXITED(st));
    return WEXITSTATUS(st);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGPIPE, SIG_IGN);
    struct rig r; unsigned slot; int rc; m11_terminal_action term; uint64_t t0; long el;

    /* A. UP throughout (PD traffic during the MAP): nothing reported. Post-MAP hold: the only end is
     *    the retaining reset, and retire is refused (no UNMAP packet). */
    start(&r, ANSWER);
    assert(m11_custodian_map(&r.cust, 4096, ms(), &slot) == 0);
    assert(r.cust.regions[slot].state == M11_SHMEM_STATE_DSP_MAP_ACKNOWLEDGED);
    assert(m11_pdr_loop_settle(&r.loop, ms()) == M11_TERMINAL_RESET_RETAINING_ANCHORS && !r.loop.down_reported);
    const uint32_t pumps_before_idle = r.glink.pd_pumps;
    assert(m11_pdr_loop_idle(&r.loop, 50, ms()) == 0 && !r.loop.down_reported);
    assert(m11_custodian_retire(&r.cust, slot, ms()) == -EPERM);
    /* Assert what idle itself does, not the cumulative MAP count: poll may observe the peer's UP
     * separately or drain it in the initial pump. The tx-after-down mutant skips one earlier pump
     * and must be killed on the no-TX-after-DOWN assertion below, independent of that scheduling. */
    assert(m11_pdr_loop_settle(&r.loop, ms()) == M11_TERMINAL_RESET_RETAINING_ANCHORS && !r.glink.pd_down &&
           r.glink.pd_pumps > pumps_before_idle);
    assert(fx_imported[r.cust.regions[slot].dma_buf_fd] && r.cust.regions[slot].vaddr);
    assert(stop(&r) == 1);
    printf("PASS UP throughout: PD traffic during the MAP changes nothing; idle wait pumps the monitor; retire refused, backing held\n");

    /* B. DOWN while the MAP is in flight: the wait ends at once, the region stays unresolved. */
    start(&r, DOWN_ON_MAP);
    t0 = ms();
    rc = m11_custodian_map(&r.cust, 4096, ms(), &slot);
    el = (long)(ms() - t0);
    assert(rc == -ENETRESET && el < 250);
    m11_shmem_region_t *g = &r.cust.regions[slot];
    assert(g->state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED && g->cause == M11_SHMEM_CAUSE_MAP_PDR && g->blocker);
    assert(r.eng.pdr_down && r.glink.pd_down && r.boot.dsp_map_attempted);
    term = m11_pdr_loop_settle(&r.loop, ms());
    assert(term == M11_TERMINAL_RESET_RETAINING_ANCHORS && (r.boot.reasons & M11_TAINT_PD_DOWN) && r.cust.kernel_imports_lost);
    assert(fx_imported[g->dma_buf_fd] && fcntl(g->dma_buf_fd, F_GETFD) != -1 && g->vaddr);
    assert(m11_shmem_unmap_and_free(&r.mgr, g) == -EBUSY && fx_imported[g->dma_buf_fd]);
    assert(m11_custodian_retire(&r.cust, slot, ms()) == -EPERM); /* post-MAP hold, before the imports-lost check */
    assert(stop(&r) == 1);
    printf("PASS DOWN during MAP: wait ends with -ENETRESET (%ld ms of 300), region unresolved (PDR), custodian told once, RESET_RETAINING_ANCHORS, backing retained\n", el);

    /* C. DOWN while an UNMAP is in flight. The custodian never starts one (post-MAP hold), so the
     *    research path is driven directly through the manager (this rig has no journal): the
     *    region stays unresolved and its backing is held. */
    start(&r, DOWN_ON_UNMAP);
    assert(m11_custodian_map(&r.cust, 4096, ms(), &slot) == 0);
    assert(m11_custodian_retire(&r.cust, slot, ms()) == -EPERM);
    g = &r.cust.regions[slot];
    rc = m11_shmem_unmap_and_free(&r.mgr, g);
    assert(rc == -ENETRESET && g->state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED && g->cause == M11_SHMEM_CAUSE_UNMAP_PDR);
    assert(m11_pdr_loop_settle(&r.loop, ms()) == M11_TERMINAL_RESET_RETAINING_ANCHORS);
    assert(fx_imported[g->dma_buf_fd] && g->vaddr);
    assert(stop(&r) == 2);
    printf("PASS DOWN during an UNMAP (research path, driven directly): region unresolved (PDR), RESET_RETAINING_ANCHORS, backing retained\n");

    /* D. DOWN just before the MAP ACK: the DOWN wins; the ACK is never adopted. */
    start(&r, DOWN_THEN_ACK);
    rc = m11_custodian_map(&r.cust, 4096, ms(), &slot);
    g = &r.cust.regions[slot];
    assert(rc == -ENETRESET && g->state == M11_SHMEM_STATE_OWNERSHIP_UNRESOLVED && g->mem_map_handle == 0);
    assert(m11_pdr_loop_settle(&r.loop, ms()) == M11_TERMINAL_RESET_RETAINING_ANCHORS);
    assert(stop(&r) == 1);
    printf("PASS DOWN before the ACK: the DOWN wins, the late ACK is not adopted\n");

    /* E. DOWN while idle: reported by the idle wait; nothing transmits afterwards. */
    start(&r, DOWN_IDLE);
    t0 = ms();
    rc = m11_pdr_loop_idle(&r.loop, 1000, ms());
    el = (long)(ms() - t0);
    assert(rc == -ENETRESET && el < 900 && r.loop.down_reported);
    assert(m11_custodian_terminal_action(&r.cust) == M11_TERMINAL_RESET_RETAINING_ANCHORS);
    assert(m11_custodian_map(&r.cust, 4096, ms(), &slot) == -EOWNERDEAD);
    uint32_t dsp = 0;
    rc = m11_gpr_engine_transact(&r.eng, M11_APM_MODULE_IID, M11_APM_CMD_GET_SPF_STATE, NULL, 0, 300, &dsp, NULL, 0, NULL);
    assert(rc == -ENETRESET && r.glink.writes == 0);
    assert(stop(&r) == 0);
    printf("INFO idle DOWN reported after %ld ms\n", el);
    printf("PASS DOWN while idle: the idle wait reports it, MAP refused, no packet ever transmitted\n");

    /* F. The monitor hangs up while idle: a lost monitor is a lost PD. */
    start(&r, HANGUP_IDLE);
    rc = m11_pdr_loop_idle(&r.loop, 1000, ms());
    assert(rc == -ENETRESET && r.glink.pd_down && r.loop.down_reported);
    assert(m11_custodian_terminal_action(&r.cust) == M11_TERMINAL_RESET_RETAINING_ANCHORS);
    assert(stop(&r) == 0);
    printf("PASS monitor hangup while idle: latched DOWN, RESET_RETAINING_ANCHORS\n");

    m11_pdr_loop bad;
    assert(m11_pdr_loop_init(&bad, NULL, NULL) == -EINVAL);
    printf("PASS G6 PDR event loop (real custodian, manager and engine; G6 transport; stand-in PD monitor)\n");
    return 0;
}
