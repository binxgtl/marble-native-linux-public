/* P5 W5 stand-in test: the speaker session under the REAL custodian, region manager, engine and intent
 * journal, the G2 transport over a SEQPACKET pair to a forked ADSP stand-in, the G3 backend over memfd
 * fixtures and the W3 ALSA backend over fixture syscalls. One event log (ALSA calls in this process, DSP
 * packets through the journal's records) checks the order: amplifier on only after the gate, off first in
 * every teardown, no UNMAP ever. No device, no firmware claim. */
#ifndef M11_CUSTODIAN_NATIVE
#error "test-speaker-session-native.c builds only with M11_CUSTODIAN_NATIVE"
#endif
#define _GNU_SOURCE
#include "speaker_session_native.h"
#include "intent_journal_native.h"
#include "gpr_transport_native.h"
#include "shmem_backend_native.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <sys/ioctl.h> /* _IO/_IOR/_IOW/_IOWR for the asound.h request numbers */
#include <sound/asound.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* ---------------- the event log ---------------- */
#define EV_MAX 512
static char ev[EV_MAX][48];
static unsigned nev;
static void evlog(const char *s) { if (nev < EV_MAX) snprintf(ev[nev++], sizeof ev[0], "%s", s); }
static int at(const char *s) { for (unsigned i = 0; i < nev; i++) if (!strcmp(ev[i], s)) return (int)i; return -1; }
static int last(const char *s) { for (unsigned i = nev; i-- > 0;) if (!strcmp(ev[i], s)) return (int)i; return -1; }
static unsigned count(const char *s) { unsigned n = 0; for (unsigned i = 0; i < nev; i++) n += !strcmp(ev[i], s); return n; }

/* ---------------- ALSA fixture (W3 shapes) ---------------- */
static struct { char path[96]; dev_t rdev; int live; } nodes[8];
static struct { int fd; dev_t rdev; int open; } afd[8];
static int a_next, a_dir, ignore_enable, foreign_enable_at_rx_hw;
static const char *elem_names[4] = {"aw_dev_0_switch", "aw_dev_1_switch", "aw_dev_0_prof", "aw_dev_1_prof"};
static unsigned elem_value[4];
static ssize_t a_read_text(const char *p, char *buf, size_t cap) {
    const char *src = NULL;
    if (!strcmp(p, "/proc/asound/pcm"))
        src = "00-32: TDM-LPAIF-RX-TERTIARY-VIRT-2 m :  : playback 1\n00-33: TDM-LPAIF-TX-TERTIARY m :  : capture 1\n";
    else if (!strcmp(p, "/sys/class/sound/pcmC0D32p/dev")) src = "116:34\n";
    else if (!strcmp(p, "/sys/class/sound/pcmC0D33c/dev")) src = "116:35\n";
    else if (!strcmp(p, "/sys/class/sound/controlC0/dev")) src = "116:1\n";
    if (!src) return -ENOENT;
    size_t n = strlen(src);
    if (n + 1 > cap) return -EFBIG;
    memcpy(buf, src, n + 1);
    return (ssize_t)n;
}
static int a_mkdir(const char *p, mode_t m) { (void)p; (void)m; if (a_dir) return -EEXIST; a_dir = 1; return 0; }
static int a_rmdir(const char *p) { (void)p; a_dir = 0; return 0; }
static int a_mknod(const char *p, mode_t m, dev_t d) {
    (void)m;
    for (int i = 0; i < 8; i++) if (!nodes[i].live) { snprintf(nodes[i].path, sizeof nodes[i].path, "%s", p); nodes[i].rdev = d; nodes[i].live = 1; return 0; }
    return -ENOSPC;
}
static int a_unlink(const char *p) { for (int i = 0; i < 8; i++) if (nodes[i].live && !strcmp(nodes[i].path, p)) { nodes[i].live = 0; return 0; } return -ENOENT; }
static int a_open(const char *p, int f) {
    (void)f;
    for (int i = 0; i < 8; i++) if (nodes[i].live && !strcmp(nodes[i].path, p))
        for (int k = 0; k < 8; k++) if (!afd[k].open) { afd[k].fd = 500 + a_next++; afd[k].rdev = nodes[i].rdev; afd[k].open = 1; return afd[k].fd; }
    return -ENOENT;
}
static int a_slot(int fd) { for (int k = 0; k < 8; k++) if (afd[k].open && afd[k].fd == fd) return k; return -1; }
static int a_fstat(int fd, struct stat *st) {
    int k = a_slot(fd); if (k < 0) return -EBADF;
    memset(st, 0, sizeof *st); st->st_mode = S_IFCHR | 0600; st->st_rdev = afd[k].rdev; return 0;
}
static int a_close(int fd) { int k = a_slot(fd); if (k < 0) return -EBADF; afd[k].open = 0; return 0; }
static const char *pcm_tag(int fd) { int k = a_slot(fd); return k >= 0 && minor(afd[k].rdev) == 34 ? "rx" : "tx"; }
static int a_ioctl(int fd, unsigned long req, void *arg) {
    int k = a_slot(fd);
    if (k < 0) return -EBADF;
    char e[48];
    if (minor(afd[k].rdev) == 1) {
        if (req == SNDRV_CTL_IOCTL_ELEM_LIST) {
            struct snd_ctl_elem_list *l = arg;
            l->count = 4;
            if (l->space) {
                for (unsigned i = 0; i < 4 && i < l->space; i++) {
                    memset(&l->pids[i], 0, sizeof l->pids[i]);
                    l->pids[i].numid = i + 1; l->pids[i].iface = SNDRV_CTL_ELEM_IFACE_MIXER;
                    snprintf((char *)l->pids[i].name, sizeof l->pids[i].name, "%s", elem_names[i]);
                }
                l->used = 4;
            }
            return 0;
        }
        if (req == SNDRV_CTL_IOCTL_ELEM_INFO) {
            struct snd_ctl_elem_info *in = arg;
            unsigned el = in->id.numid - 1, it = in->value.enumerated.item;
            static const char *sw[] = {"Disable", "Enable"}, *pf[] = {"Music", "Voice"};
            in->type = SNDRV_CTL_ELEM_TYPE_ENUMERATED; in->count = 1; in->value.enumerated.items = 2;
            if (it < 2) snprintf(in->value.enumerated.name, sizeof in->value.enumerated.name, "%s", el < 2 ? sw[it] : pf[it]);
            return 0;
        }
        if (req == SNDRV_CTL_IOCTL_ELEM_WRITE) {
            struct snd_ctl_elem_value *v = arg;
            unsigned el = v->id.numid - 1, val = v->value.enumerated.item[0];
            if (el < 2) { snprintf(e, sizeof e, "sw%u=%s", el, val ? "Enable" : "Disable"); evlog(e); }
            if (!(ignore_enable && el < 2 && val == 1)) elem_value[el] = val;
            return 0;
        }
        if (req == SNDRV_CTL_IOCTL_ELEM_READ) {
            struct snd_ctl_elem_value *v = arg;
            v->value.enumerated.item[0] = elem_value[v->id.numid - 1];
            return 0;
        }
        return -ENOTTY;
    }
    const char *t = pcm_tag(fd);
    if (req == SNDRV_PCM_IOCTL_HW_PARAMS) {
        struct snd_pcm_hw_params *h = arg;
        for (int n = SNDRV_PCM_HW_PARAM_FIRST_INTERVAL; n <= SNDRV_PCM_HW_PARAM_LAST_INTERVAL; n++) {
            struct snd_interval *i = &h->intervals[n - SNDRV_PCM_HW_PARAM_FIRST_INTERVAL];
            i->max = i->min; i->integer = 1;
        }
        snprintf(e, sizeof e, "%s_hw", t); evlog(e);
        if (foreign_enable_at_rx_hw && t[0] == 'r') elem_value[0] = 1; /* someone else enables amplifier 0 */
        return 0;
    }
    if (req == SNDRV_PCM_IOCTL_SW_PARAMS) return 0;
    if (req == SNDRV_PCM_IOCTL_PREPARE) { snprintf(e, sizeof e, "%s_prepare", t); evlog(e); return 0; }
    if (req == SNDRV_PCM_IOCTL_DROP) { snprintf(e, sizeof e, "%s_drop", t); evlog(e); return 0; }
    return -ENOTTY;
}
static const m11_snd_sys asys = {a_open, a_fstat, a_close, a_ioctl, a_mknod, a_unlink, a_mkdir, a_rmdir, a_read_text};

/* ---------------- memfd shmem fixture (G7 test shapes) ---------------- */
static int fx_heap = -1, fx_ion = -1;
static int fx_ioctl(int fd, unsigned long req, void *arg) {
    if (req == M11_DMA_HEAP_IOCTL_ALLOC) {
        m11_dma_heap_allocation_data *d = arg;
        assert(fd == fx_heap);
        int m = memfd_create("m11-spk", MFD_CLOEXEC);
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

/* ---------------- the ADSP stand-in ---------------- */
typedef struct {
    uint32_t fail_op;       /* answer this opcode (its fail_nth occurrence) with IBASIC status 1 */
    unsigned fail_nth;
    uint32_t fail_status;   /* zero selects historical status 1; otherwise preserve all 32 bits */
    int drop_inband_cfg;
    uint32_t drop_op;       /* never answer this opcode */
    int bad_re;             /* GET_CFG reports another Re */
    unsigned wr_delay_ms;   /* delay each BUFFER_DONE */
    uint32_t eos_ibasic;    /* nonzero: an IBASIC with this status for the EOS before its EOS_RENDERED */
    uint32_t eos_render;    /* nonzero: this render status instead of 1 (rendered) */
} peer_cfg;

static void reply(int ep, const m11_gpr_hdr_t *h, uint32_t opcode, const void *pl, size_t n) {
    uint8_t tx[160]; size_t txl = 0;
    if (m11_gpr_pack_packet_ex(tx, sizeof tx, &txl, M11_GPR_DOMAIN_APPS, M11_GPR_DOMAIN_ADSP, 0,
                               h->src_port, h->dst_port, h->token, opcode, pl, n) < 0) _exit(104);
    (void)send(ep, tx, txl, 0);
}
static void peer(int ep, peer_cfg c) {
    alarm(20);
    unsigned seen_fail = 0, maps = 0, unmaps = 0;
    uint32_t q12[2] = {0, 0};
    int read_ch = -1; /* the channel the last stock read command selected */
    for (;;) {
        uint8_t rx[M11_GPR_MAX_PKT_BYTES];
        ssize_t n = recv(ep, rx, sizeof rx, 0);
        if (n <= 0) _exit(unmaps ? 90 : 0);
        m11_gpr_hdr_t h; const uint8_t *pl; size_t pll;
        if (m11_gpr_validate_packet(rx, (size_t)n, &h, &pl, &pll) < 0) _exit(100);
        if (h.opcode == M11_APM_CMD_SHARED_MEM_UNMAP_REGIONS || h.opcode == M11_APM_CMD_CLOSE_ALL) { unmaps++; continue; }
        if (h.opcode == c.drop_op) continue;
        if (c.drop_inband_cfg && h.opcode == M11_APM_CMD_SET_CFG && pll > sizeof(m11_apm_cmd_header_t)) continue;
        if (h.opcode == c.fail_op && ++seen_fail == c.fail_nth) {
            m11_gpr_ibasic_rsp_t r = {.cmd_opcode = h.opcode, .status = c.fail_status ? c.fail_status : 1};
            reply(ep, &h, M11_GPR_IBASIC_RSP_RESULT, &r, sizeof r);
            continue;
        }
        if (h.opcode == M11_APM_CMD_SHARED_MEM_MAP_REGIONS) {
            m11_apm_rsp_shared_mem_map_t r = {.mem_map_handle = 0xA0000001u + maps++};
            reply(ep, &h, M11_APM_CMDRSP_SHARED_MEM_MAP_REGIONS, &r, sizeof r);
        } else if (h.opcode == M11_APM_CMD_GET_CFG) {
            /* the stock read only (libawcal aw_audioreach_read_msg_from_dsp): a read command came first */
            m11_aw_msg_kind_t kind = 0;
            if (m11_aw_classify_cfg_pkt(rx, (size_t)n, &kind, NULL, NULL) < 0 || kind != M11_AW_MSG_READ || read_ch < 0)
                _exit(105);
            uint8_t out[160]; size_t ol = 0;
            uint32_t v = q12[read_ch] + (c.bad_re ? 2048u : 0u);
            read_ch = -1;
            if (m11_aw_pack_read_rsp_pkt(out, sizeof out, &ol, h.src_port, h.token, 0u, 0u, 4u, v) < 0) _exit(106);
            (void)send(ep, out, ol, 0);
        } else if (h.opcode == M11_APM_CMD_SET_CFG && h.dst_port == 0x42D3u) {
            m11_aw_msg_kind_t kind = 0;
            uint32_t ch = 0, v = 0;
            if (m11_aw_classify_cfg_pkt(rx, (size_t)n, &kind, &ch, &v) < 0 || kind == M11_AW_MSG_READ || ch > 1) _exit(107);
            if (kind == M11_AW_MSG_WRITE) q12[ch] = v; else read_ch = (int)ch;
            m11_gpr_ibasic_rsp_t r = {.cmd_opcode = h.opcode, .status = 0};
            reply(ep, &h, M11_GPR_IBASIC_RSP_RESULT, &r, sizeof r);
        } else if (h.opcode == M11_DATA_CMD_WR_SH_MEM_EP_DATA_BUFFER_V2) {
            if (c.wr_delay_ms) { struct timespec t = {0, (long)c.wr_delay_ms * 1000000L}; nanosleep(&t, NULL); }
            uint32_t w[8] = {0};
            memcpy(w, pl, 12); /* echo address and map handle */
            reply(ep, &h, M11_DATA_CMD_RSP_WR_SH_MEM_EP_DATA_BUFFER_DONE_V2, w, sizeof w);
        } else if (h.opcode == M11_DATA_CMD_RD_SH_MEM_EP_DATA_BUFFER_V2) {
            uint32_t w[14] = {0};
            reply(ep, &h, M11_DATA_CMD_RSP_RD_SH_MEM_EP_DATA_BUFFER_DONE_V2, w, sizeof w);
        } else if (h.opcode == M11_DATA_CMD_WR_SH_MEM_EP_EOS) {
            if (c.eos_ibasic) {
                m11_gpr_ibasic_rsp_t ib = {.cmd_opcode = h.opcode, .status = c.eos_ibasic};
                reply(ep, &h, M11_GPR_IBASIC_RSP_RESULT, &ib, sizeof ib);
            }
            uint32_t w[2] = {h.dst_port, c.eos_render ? c.eos_render : 1u}; /* render status 1: rendered */
            reply(ep, &h, M11_DATA_CMD_RSP_WR_SH_MEM_EP_EOS_RENDERED, w, sizeof w);
        } else {
            m11_gpr_ibasic_rsp_t r = {.cmd_opcode = h.opcode, .status = 0};
            reply(ep, &h, M11_GPR_IBASIC_RSP_RESULT, &r, sizeof r);
        }
    }
}

/* ---------------- the journal sink: every record lands in the event log ---------------- */
static int jsink_append(void *user, const char *rec, size_t len) {
    (void)user; (void)len;
    const char *op = strstr(rec, " op=");
    const char *dst = strstr(rec, " dst=");
    if (!op || !dst) return -EIO;
    char e[48];
    unsigned opv = (unsigned)strtoul(op + 4, NULL, 16), dstv = (unsigned)strtoul(dst + 5, NULL, 16);
    snprintf(e, sizeof e, "op=%08x dst=%x", opv, dstv);
    evlog(e);
    return 0;
}
static const m11_intent_sink jsink = {jsink_append, NULL};

/* ---------------- the rig ---------------- */
static uint64_t ms(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u;
}
static uint64_t now_cb(void *u) { (void)u; return ms(); }
struct rig {
    int sv[2]; pid_t pid;
    m11_pid1_anchor ep, ion; m11_gpr_native_link glink; m11_gpr_transport_t inner, t; m11_intent_link ilink;
    m11_gpr_engine_t eng; m11_shmem_native_link slink; m11_shmem_backend_t b; m11_shmem_mgr_t mgr;
    m11_boot_ledger boot; m11_custodian cust; m11_snd_backend snd;
};
static int map_cb(void *u, size_t bytes, unsigned *slot) { struct rig *r = u; return m11_custodian_map(&r->cust, bytes, ms(), slot); }
static unsigned nrec, nsettle;
static char cfg_records[16][160];
static unsigned ncfg_records;
static char re_records[8][192];
static unsigned nre_records;
static char eos_record[192];
static FILE *rec_out; /* M11_SPK_RECORDS: the happy path's records as speaker_entry_main writes them (P5 check cross-check) */
static void record_cb(void *u, const char *line) {
    (void)u; nrec++;
    if (strstr(line, "phase=spk cfg_rsp ") == line) {
        assert(ncfg_records < 16);
        snprintf(cfg_records[ncfg_records++], sizeof cfg_records[0], "%s", line);
    }
    if (strstr(line, "phase=spk eos_rsp ") == line) snprintf(eos_record, sizeof eos_record, "%s", line);
    if (strstr(line, "phase=spk re_rsp ") == line) {
        assert(nre_records < 8);
        snprintf(re_records[nre_records++], sizeof re_records[0], "%s", line);
    }
    if (rec_out) fprintf(rec_out, "<6>M11SPK v=1 boot=7 %s\n", line);
}
static void settle_cb(void *u) { (void)u; nsettle++; }
static int read_remote_errno(void *u, int fd, uint8_t *b, size_t cap, uint32_t ms_) {
    (void)u; (void)fd; (void)b; (void)cap; (void)ms_;
    return -EREMOTEIO; /* transport errno, NOT a DSP NACK */
}

static void start(struct rig *r, peer_cfg c) {
    memset(r, 0, sizeof *r);
    nev = 0; nrec = 0; nsettle = 0; ignore_enable = 0; foreign_enable_at_rx_hw = 0; a_dir = 0; a_next = 0;
    ncfg_records = 0; nre_records = 0; eos_record[0] = '\0';
    memset(nodes, 0, sizeof nodes); memset(afd, 0, sizeof afd); memset(elem_value, 0, sizeof elem_value);
    elem_value[2] = elem_value[3] = 1; /* profiles start at Voice: the plan sets Music */
    if (fx_heap < 0) fx_heap = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (fx_ion < 0) fx_ion = open("/dev/null", O_RDWR | O_CLOEXEC);
    assert(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, r->sv) == 0);
    r->pid = fork(); assert(r->pid >= 0);
    if (r->pid == 0) { close(r->sv[0]); peer(r->sv[1], c); }
    close(r->sv[1]);
    r->ep.state = M11_ANCHOR_HELD; r->ep.anchor_fd = r->sv[0]; r->ep.owner_pid = getpid();
    r->ion.state = M11_ANCHOR_HELD; r->ion.anchor_fd = fx_ion; r->ion.owner_pid = getpid();
    assert(m11_model_new_boot(&r->boot, 7, ms()) == 0);
    assert(m11_gpr_native_transport(&r->glink, &r->ep, &r->inner) == 0);
    assert(m11_intent_transport(&r->ilink, &r->inner, &jsink, &r->boot, &r->t) == 0);
    assert(m11_gpr_engine_init(&r->eng, &r->t, 0x0100u) == 0 && m11_gpr_engine_open(&r->eng) == 0);
    assert(m11_shmem_native_backend(&r->slink, &r->ion, fx_heap, &fx_sys, &r->b) == 0);
    assert(m11_shmem_mgr_init(&r->mgr, &r->b, &r->eng, 500) == 0);
    const m11_custodian_model_contract ct = {true, true, true, true, true, true, true};
    assert(m11_custodian_init(&r->cust, &r->boot, &r->mgr, &ct, 2000) == 0);
    m11_snd_paths sp = m11_snd_paths_default();
    assert(m11_snd_prepare(&r->snd, &asys, &sp, "TDM-LPAIF-RX-TERTIARY-VIRT-2", "TDM-LPAIF-TX-TERTIARY") == 0);
}
/* W5b: every DSP command of every scenario was the custodian's own traffic */
static int stop(struct rig *r) {
    assert(!(r->boot.reasons & M11_TAINT_FOREIGN_TRAFFIC));
    m11_snd_release(&r->snd);
    close(r->sv[0]);
    int st; assert(waitpid(r->pid, &st, 0) == r->pid && WIFEXITED(st));
    return WEXITSTATUS(st);
}

/* ---------------- a synthetic plan in the generator's format ---------------- */
static uint8_t plan_buf[200000];
static size_t pl_at;
static void put32(uint32_t v) { memcpy(plan_buf + pl_at, &v, 4); pl_at += 4; }
/* the generator's pad8(payload): the blob's own length is padded, wherever the blob starts */
static void putb(const void *p, size_t n) { memcpy(plan_buf + pl_at, p, n); pl_at += n; for (; n % 8; n++) plan_buf[pl_at++] = 0; }
static size_t sec_begin(uint32_t type) { put32(type); size_t at = pl_at; put32(0); return at; }
static void sec_end(size_t at) { uint32_t n = (uint32_t)(pl_at - at - 4); memcpy(plan_buf + at, &n, 4); while (pl_at % 8) plan_buf[pl_at++] = 0; }
static void param(uint8_t *out, size_t *len, uint32_t miid, uint32_t pid, uint32_t v) {
    uint32_t w[6] = {miid, pid, 4, 0, v, 0};
    memcpy(out + *len, w, sizeof w); *len += sizeof w;
}
static void put_graph(uint32_t id, const uint32_t *sgs, uint32_t nsg, uint32_t ncfg) {
    size_t s = sec_begin(1);
    put32(id); put32(nsg); for (uint32_t i = 0; i < nsg; i++) put32(sgs[i]);
    uint8_t blob[96]; size_t bl = 0;
    param(blob, &bl, 1, 0x08001001, id); param(blob, &bl, 1, 0x08001002, id);
    put32((uint32_t)bl); putb(blob, bl);                      /* open */
    bl = 0; param(blob, &bl, 0x4008, 0x08001035, 0x2000);
    put32((uint32_t)bl); putb(blob, bl);                      /* cal */
    put32(ncfg);
    for (uint32_t i = 0; i < ncfg; i++) { bl = 0; param(blob, &bl, 0x428F, 0x08001017 + i, i); put32((uint32_t)bl); putb(blob, bl); }
    sec_end(s);
}
static size_t media_sig_at, media_pcm_at;
static size_t build_plan_mode(uint32_t duration_ms, int imported) {
    memset(plan_buf, 0, sizeof plan_buf);
    pl_at = 64;
    static const uint32_t vi_sgs[] = {0xB00000D5, 0xB00000CE}, rx_sgs[] = {0xB0000002, 0xB0000025, 0xB0000024, 0xB0000023};
    put_graph(1, vi_sgs, 2, 3);
    put_graph(2, rx_sgs, 4, 6);
    size_t s = sec_begin(2);
    uint32_t ids[14] = {0x40BD, 0x4547, 0x42D3, 0x42D4, 0x428F, 0x4308, 0x4008, 48000, 2, 2, 48000, 2, 2, 8};
    for (int i = 0; i < 14; i++) put32(ids[i]);
    sec_end(s);
    s = sec_begin(3);
    uint32_t be0[6] = {0, 96000, 3, SNDRV_PCM_FORMAT_S32_LE, 682, 2}, be1[6] = {1, 96000, 2, SNDRV_PCM_FORMAT_S32_LE, 1024, 2};
    char nm[64];
    for (int i = 0; i < 6; i++) put32(be0[i]);
    memset(nm, 0, sizeof nm); strcpy(nm, "TDM-LPAIF-RX-TERTIARY-VIRT-2"); memcpy(plan_buf + pl_at, nm, 64); pl_at += 64;
    for (int i = 0; i < 6; i++) put32(be1[i]);
    memset(nm, 0, sizeof nm); strcpy(nm, "TDM-LPAIF-TX-TERTIARY"); memcpy(plan_buf + pl_at, nm, 64); pl_at += 64;
    sec_end(s);
    s = sec_begin(4);
    for (int i = 0; i < 2; i++) {
        char c[64]; memset(c, 0, sizeof c);
        snprintf(c, 44, "aw_dev_%d_prof", i); strcpy(c + 44, "Music");
        memcpy(plan_buf + pl_at, c, 64); pl_at += 64;
    }
    sec_end(s);
    s = sec_begin(5); put32(6372); put32(7003); sec_end(s);
    s = sec_begin(6); media_sig_at = pl_at;
    put32(duration_ms); put32(imported ? 0 : 10); put32(imported ? 0 : 1); put32((uint32_t)-10000);
    put32(imported ? 1 : 0); if (!imported) put32(440); sec_end(s);
    s = sec_begin(7);
    media_pcm_at = pl_at;
    uint32_t bytes = 48000u * duration_ms / 1000u * 4u;
    for (uint32_t i = 0; i < bytes; i++) plan_buf[pl_at++] = imported ? 0 : (uint8_t)(i * 7u);
    sec_end(s);
    memcpy(plan_buf, "M11SPK01", 8);
    uint32_t hdr[4] = {1, (uint32_t)pl_at, 8, 64};
    memcpy(plan_buf + 8, hdr, sizeof hdr);
    return pl_at;
}
static size_t build_plan(uint32_t duration_ms) { return build_plan_mode(duration_ms, 0); }

static m11_speaker_plan plan;
static int run_session(struct rig *r, m11_speaker_report *rep, uint32_t window_ms) {
    m11_speaker_io io = {.cust = &r->cust, .map_fn = map_cb, .user = r,
        .snd = &r->snd, .plan = &plan, .record_fn = record_cb, .settle_fn = settle_cb, .now_fn = now_cb, .wait_timeout_ms = 300,
        .eos_timeout_ms = 300, .amp_window_ms = window_ms, .region_bytes = 65536, .write_buffers = 4, .buffer_ms = 40};
    return m11_speaker_session_run(&io, rep);
}
static char op_ev[48];
static const char *op(uint32_t opcode, uint32_t dst) { snprintf(op_ev, sizeof op_ev, "op=%08x dst=%x", opcode, dst); return op_ev; }

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGPIPE, SIG_IGN);
    struct rig r; m11_speaker_report rep; int rc;

    /* plan parsing */
    size_t media_len = build_plan_mode(500, 1);
    m11_speaker_plan media;
    assert(m11_speaker_plan_parse(plan_buf, media_len, &media) == 0 && media.signal_kind == 1 && !media.num_tones);
    const size_t fields[] = {0, 4, 8, 12, 16};
    const uint32_t wrong[] = {501, 10, 1, (uint32_t)-6000, 2};
    for (unsigned i = 0; i < 5; ++i) {
        uint32_t saved; memcpy(&saved, plan_buf + media_sig_at + fields[i], 4);
        memcpy(plan_buf + media_sig_at + fields[i], &wrong[i], 4);
        assert(m11_speaker_plan_parse(plan_buf, media_len, &media) == -EBADMSG);
        memcpy(plan_buf + media_sig_at + fields[i], &saved, 4);
    }
    const int16_t loud[] = {10362, -32768};
    for (unsigned i = 0; i < 2; ++i) {
        memcpy(plan_buf + media_pcm_at + 8, &loud[i], 2);
        assert(m11_speaker_plan_parse(plan_buf, media_len, &media) == -EBADMSG);
    }
    memset(plan_buf + media_pcm_at + 8, 0, 2);
    plan_buf[media_pcm_at] = 2;
    assert(m11_speaker_plan_parse(plan_buf, media_len, &media) == -EBADMSG);
    puts("PASS imported PCM parser: exact duration, source kind, peak cap and silent edges; malformed metadata/loud samples refused");
    size_t plen = build_plan(500);
    assert(m11_speaker_plan_parse(plan_buf, plen, &plan) == 0);
    assert(plan.vi.num_sgs == 2 && plan.rx.num_sgs == 4 && plan.rx.num_cfgs == 6 && plan.vi.num_cfgs == 3);
    assert(plan.wr_ep == 0x40BD && plan.sp_rx == 0x42D3 && plan.volume_level == 8 && plan.re_mohm[1] == 7003);
    assert(plan.pcm.len == 96000 && !strcmp(plan.backend[0].name, "TDM-LPAIF-RX-TERTIARY-VIRT-2") && plan.num_controls == 2);
    m11_speaker_plan bad;
    assert(m11_speaker_plan_parse(plan_buf, plen - 8, &bad) == -EBADMSG);
    plan_buf[0] ^= 1; assert(m11_speaker_plan_parse(plan_buf, plen, &bad) == -EBADMSG); plan_buf[0] ^= 1;
    uint32_t keep; memcpy(&keep, plan_buf + 64, 4); uint32_t t2 = 2; memcpy(plan_buf + 64, &t2, 4);
    assert(m11_speaker_plan_parse(plan_buf, plen, &bad) == -EBADMSG); memcpy(plan_buf + 64, &keep, 4);
    assert(m11_speaker_plan_parse(plan_buf, plen, &plan) == 0);
    puts("PASS plan: generator format parsed (graphs, IDs, back ends, controls, Re, PCM); truncation, magic and section order refused");

    /* 1. the happy path: stock order, amplifier on only after the gate, off first, no UNMAP */
    start(&r, (peer_cfg){0});
    const char *rec_path = getenv("M11_SPK_RECORDS");
    if (rec_path) assert((rec_out = fopen(rec_path, "w")) != NULL);
    rc = run_session(&r, &rep, 5000);
    if (rec_out) { assert(fclose(rec_out) == 0); rec_out = NULL; }
    printf("INFO happy rc=%d stage=%d sent=%u done=%u bytes=%u eos=%d events=%u records=%u\n",
           rc, rep.stage, rep.buffers_sent, rep.buffers_done, rep.bytes_played, rep.eos_rc, nev, nrec);
    assert(rc == 0 && rep.stage == M11_SPK_EOS && rep.amp_off_verified && !rep.teardown_rc);
    assert(rep.bytes_played == 96000 && rep.buffers_sent == 13 && rep.buffers_done == 13 && rep.rd_queued == 2);
    assert(rep.re.pair_re_readback_verified && rep.regions_mapped == 2);
    assert(ncfg_records == 9);
    /* the EOS as received: no IBASIC, one EOS_RENDERED of 8 bytes from the WR end point, render status 1 */
    assert(strstr(eos_record, " submit=0 tx=4 wait=0 dsp=00000000 ib=0/00000000 ren=1/8/40bd/40bd/1 ev=0/0/0 drop=0/0"));
    /* Re per channel: the write, the stock read command, the read; the read returns the value written */
    assert(nre_records == 6);
    assert(strstr(re_records[0], "op=01001006 req=28/0/10013d1b valid=1 status=00000000 rc=0 len=0"));
    assert(strstr(re_records[1], "op=01001006 req=24/1/10013d1b valid=1 status=00000000 rc=0 len=0"));
    assert(strstr(re_records[2], "op=01001007 req=8/0/00000000 valid=1 status=00000000 rc=0 len=28 rsp=4/00000000/26099"));
    assert(strstr(re_records[4], "req=24/1/10013d1c") && strstr(re_records[5], "rsp=4/00000000/28684"));
    for (unsigned i = 0; i < ncfg_records; ++i)
        assert(strstr(cfg_records[i], "valid=1 status=00000000 rc=0"));
    assert(nsettle >= 50); /* the caller's settle after every custodian call and wait */
    int vi_open = at(op(M11_APM_CMD_GRAPH_OPEN, 1)), rx_open = last(op(M11_APM_CMD_GRAPH_OPEN, 1));
    assert(vi_open >= 0 && rx_open > vi_open && count(op(M11_APM_CMD_SHARED_MEM_MAP_REGIONS, 1)) == 2);
    assert(at("tx_hw") < vi_open && at("rx_hw") > vi_open && at("rx_hw") < rx_open);
    assert(at("tx_prepare") > at(op(M11_DATA_CMD_RD_SH_MEM_EP_DATA_BUFFER_V2, 0x4547)));
    int rx_start = last(op(M11_APM_CMD_GRAPH_START, 1)), amp_on = at("sw0=Enable"), amp_off = last("sw0=Disable");
    assert(amp_on > rx_start && last("sw1=Enable") < at("rx_prepare") && at("rx_prepare") < at(op(M11_DATA_CMD_WR_SH_MEM_EP_DATA_BUFFER_V2, 0x40BD)));
    assert(at(op(M11_DATA_CMD_WR_SH_MEM_EP_EOS, 0x40BD)) < amp_off && last("sw1=Disable") > amp_on);
    int rx_stop = at(op(M11_APM_CMD_GRAPH_STOP, 1));
    assert(amp_off < rx_stop && rx_stop < at("rx_drop") && at("rx_drop") < last(op(M11_APM_CMD_GRAPH_STOP, 1)));
    assert(last(op(M11_APM_CMD_GRAPH_STOP, 1)) < at("tx_drop") && at("tx_drop") < at(op(M11_APM_CMD_GRAPH_CLOSE, 1)));
    assert(count(op(M11_APM_CMD_GRAPH_CLOSE, 1)) == 2 && count(op(M11_APM_CMD_GRAPH_START, 1)) == 2);
    /* calibrations to APM; single-parameter configs to their module (stock rule); Re SET and GET to 0x42D3 */
    assert(count(op(M11_APM_CMD_SET_CFG, 1)) == 2 && count(op(M11_APM_CMD_SET_CFG, 0x428F)) == 3 + 6);
    /* per channel the write and the read command (SET_CFG), then the read (GET_CFG) */
    assert(count(op(M11_APM_CMD_SET_CFG, 0x42D3)) == 4 && count(op(M11_APM_CMD_GET_CFG, 0x42D3)) == 2);
    for (unsigned i = 0; i < M11_CUSTODIAN_REGIONS; i++) {
        if (r.cust.occupied[i]) assert(r.cust.regions[i].state == M11_SHMEM_STATE_DSP_MAP_ACKNOWLEDGED && r.cust.regions[i].map_tx_started);
        assert(r.cust.region_graph_refs[i] == 0);
    }
    /* W5b: each out-of-band payload kept its own 4 KiB place in the command region (the first MAP), never reused */
    const uint8_t *cmdr = r.cust.regions[0].vaddr;
    assert(!memcmp(cmdr, plan.vi.open.data, plan.vi.open.len) && !memcmp(cmdr + 4096, plan.vi.cal.data, plan.vi.cal.len) && !memcmp(cmdr + 8192, plan.rx.open.data, plan.rx.open.len) && !memcmp(cmdr + 12288, plan.rx.cal.data, plan.rx.cal.len));
    /* W5b: both graphs went through the custodian's ledger and were closed there; the boot stays CLEAN */
    assert(r.cust.graphs[0].state == M11_GRAPH_FREE && r.cust.graphs[1].state == M11_GRAPH_FREE && r.boot.state == M11_ADSP_CLEAN);
    assert(stop(&r) == 0); /* the stand-in saw no UNMAP and no CLOSE_ALL */
    puts("PASS happy path: back ends before graphs, VI before RX, Re read back, gate, amplifier on, RX prepare, 13 buffers, EOS; amplifier off first, then stop, back-end close and close in order; regions held, no UNMAP");

    /* 2. RX START refused: never an amplifier write, and what started is undone */
    start(&r, (peer_cfg){.fail_op = M11_APM_CMD_GRAPH_START, .fail_nth = 2});
    rc = run_session(&r, &rep, 5000);
    assert(rc == -EREMOTEIO && rep.fail_step == M11_SPK_RX_START && !rep.amp_touched && !rep.rx_started);
    assert(at("sw0=Enable") < 0 && at("sw1=Enable") < 0 && count(op(M11_APM_CMD_GRAPH_STOP, 1)) == 1);
    assert(at("rx_drop") >= 0 && at("tx_drop") >= 0 && count(op(M11_APM_CMD_GRAPH_CLOSE, 1)) == 2);
    assert(stop(&r) == 0);
    /* 3. Re read back differs: no amplifier write */
    start(&r, (peer_cfg){.bad_re = 1});
    rc = run_session(&r, &rep, 5000);
    assert(rc < 0 && rep.fail_step == M11_SPK_RX_RE && !rep.amp_touched && at("sw0=Enable") < 0);
    assert(at(op(M11_APM_CMD_GRAPH_PREPARE, 1)) >= 0 && count(op(M11_APM_CMD_GRAPH_PREPARE, 1)) == 1);
    assert(stop(&r) == 0);
    puts("PASS before the gate: a refused RX START or a Re read-back that differs never writes Enable; started graphs stopped, back ends closed, graphs closed");
    /* 3b. an amplifier switch found Enable at the gate (someone else wrote it): the session never writes
     * Enable, and the teardown drives both switches Disable and reads them back */
    start(&r, (peer_cfg){0});
    foreign_enable_at_rx_hw = 1;
    rc = run_session(&r, &rep, 5000);
    assert(rc == -EIO && rep.fail_step == M11_SPK_GATE && !rep.amp_on && at("sw0=Enable") < 0 &&
           last("sw0=Disable") > at("rx_hw") && rep.amp_off_verified);
    assert(stop(&r) == 0);
    puts("PASS gate: a switch found Enable stops the session before Enable is ever written; the teardown drives it Disable");

    /* 4. a buffer refused while playing: amplifier off first, verified */
    start(&r, (peer_cfg){.fail_op = M11_DATA_CMD_WR_SH_MEM_EP_DATA_BUFFER_V2, .fail_nth = 6});
    rc = run_session(&r, &rep, 5000);
    assert(rc == -EREMOTEIO && rep.fail_step == M11_SPK_PLAYED && rep.amp_on && rep.amp_off_verified);
    assert(last("sw0=Disable") < at(op(M11_APM_CMD_GRAPH_STOP, 1)) && last("sw1=Disable") < at(op(M11_APM_CMD_GRAPH_STOP, 1)));
    assert(at(op(M11_DATA_CMD_WR_SH_MEM_EP_EOS, 0x40BD)) < 0);
    assert(stop(&r) == 0);
    /* 5. the Enable does not read back: the switches are still driven Disable */
    start(&r, (peer_cfg){0});
    ignore_enable = 1;
    rc = run_session(&r, &rep, 5000);
    assert(rc == -EIO && rep.fail_step == M11_SPK_AMP_ON && rep.amp_touched && !rep.amp_on && rep.amp_off_verified);
    assert(at("rx_prepare") < 0 && at(op(M11_DATA_CMD_WR_SH_MEM_EP_DATA_BUFFER_V2, 0x40BD)) < 0);
    assert(stop(&r) == 0);
    /* 6. the amplifier window: slow buffers stop the stream */
    start(&r, (peer_cfg){.wr_delay_ms = 60});
    rc = run_session(&r, &rep, 150);
    assert(rc == -ETIME && rep.fail_step == M11_SPK_PLAYED && rep.amp_off_verified && rep.amp_off_ms - rep.amp_on_ms < 1500);
    assert(stop(&r) == 0);
    /* 7. no EOS RENDERED: amplifier off */
    start(&r, (peer_cfg){.drop_op = M11_DATA_CMD_WR_SH_MEM_EP_EOS});
    rc = run_session(&r, &rep, 5000);
    assert(rc == -ETIMEDOUT && rep.fail_step == M11_SPK_EOS && rep.amp_off_verified && rep.bytes_played == 96000);
    assert(strstr(eos_record, " wait=-110 ") && strstr(eos_record, " ib=0/00000000 ren=0/0/0/0/0 "));
    assert(stop(&r) == 0);
    /* Run29: an IBASIC error for the EOS before its EOS_RENDERED 1 (stock gsl_gpr_callback frees it): played */
    start(&r, (peer_cfg){.eos_ibasic = 0x12});
    rc = run_session(&r, &rep, 5000);
    assert(rc == 0 && rep.eos_rc == 0 && rep.amp_off_verified);
    assert(strstr(eos_record, " wait=0 dsp=00000000 ib=1/00000012 ren=1/8/40bd/40bd/1 "));
    assert(stop(&r) == 0);
    /* EOS dropped (render status 2) stays a failure, raw status on record, amplifier off first */
    start(&r, (peer_cfg){.eos_render = 2});
    rc = run_session(&r, &rep, 5000);
    assert(rc == -EREMOTEIO && rep.fail_step == M11_SPK_EOS && rep.amp_off_verified);
    assert(strstr(eos_record, " wait=-121 dsp=00000002 ib=0/00000000 ren=1/8/40bd/40bd/2 "));
    assert(stop(&r) == 0);
    puts("PASS after the gate: a refused buffer, an Enable that does not read back, the amplifier window and a missing EOS each end with the switches driven and read back Disable before any stop");

    /* 8. a profile item missing: nothing mapped, nothing sent */
    start(&r, (peer_cfg){0});
    strcpy(plan.control[1].value, "Ringtone");
    rc = run_session(&r, &rep, 5000);
    assert(rc == -ENOENT && rep.fail_step == M11_SPK_AMP_OFF && rep.regions_mapped == 0 && !rep.amp_touched);
    assert(count(op(M11_APM_CMD_SHARED_MEM_MAP_REGIONS, 1)) == 0);
    strcpy(plan.control[1].value, "Music");
    assert(stop(&r) == 0);
    puts("PASS pre-checks: a control the kernel does not offer stops the session before any MAP");

    /* 9. W5b: the VI GRAPH_OPEN reply never comes: the ledger keeps that graph UNKNOWN, the teardown never
     * commands it again (no STOP, no CLOSE) and reports it; the back end is still closed */
    start(&r, (peer_cfg){.drop_op = M11_APM_CMD_GRAPH_OPEN});
    rc = run_session(&r, &rep, 5000);
    assert(rc == -ETIMEDOUT && rep.fail_step == M11_SPK_VI_OPEN && rep.vi_opened && rep.teardown_rc == -EOWNERDEAD);
    assert(r.cust.graphs[0].state == M11_GRAPH_UNKNOWN && (r.boot.reasons & M11_TAINT_GRAPH_UNKNOWN) && !rep.amp_touched);
    assert(count(op(M11_APM_CMD_GRAPH_OPEN, 1)) == 1 && count(op(M11_APM_CMD_GRAPH_STOP, 1)) == 0 &&
           count(op(M11_APM_CMD_GRAPH_CLOSE, 1)) == 0 && at("tx_drop") >= 0);
    assert(stop(&r) == 0);
    puts("PASS ledger: a GRAPH_OPEN without its reply stays UNKNOWN and is never commanded again; the back end is closed");

    /* Run28: preserve the matched DSP status, including UINT32_MAX (not a sentinel).
     * The first SET_CFG is OOB calibration, the second is the first VI in-band config. */
    start(&r, (peer_cfg){.fail_op=M11_APM_CMD_SET_CFG, .fail_nth=2, .fail_status=UINT32_MAX});
    rc = run_session(&r, &rep, 5000);
    assert(rc == -EREMOTEIO && rep.fail_step == M11_SPK_VI_CFG && !rep.amp_touched);
    assert(ncfg_records == 1 && strstr(cfg_records[0], "valid=1 status=ffffffff rc=-121"));
    assert(stop(&r) == 0);
    start(&r, (peer_cfg){.drop_inband_cfg=1});
    rc = run_session(&r, &rep, 5000);
    assert(rc == -ETIMEDOUT && rep.fail_step == M11_SPK_VI_CFG && !rep.amp_touched);
    assert(ncfg_records == 1 && strstr(cfg_records[0], "valid=0 status=00000000 rc=-110"));
    assert(stop(&r) == 0);
    /* the Re read command refused (SET_CFG 13: VI cal, 3 VI, RX cal, 6 RX, the ch0 write, then the read command):
     * rx_re fails with the DSP status on record, no GET_CFG follows, no amplifier write */
    start(&r, (peer_cfg){.fail_op=M11_APM_CMD_SET_CFG, .fail_nth=13, .fail_status=0x12});
    rc = run_session(&r, &rep, 5000);
    assert(rc == -EREMOTEIO && rep.fail_step == M11_SPK_RX_RE && !rep.amp_touched && at("sw0=Enable") < 0);
    assert(nre_records == 2 && strstr(re_records[1], "op=01001006 req=24/1/10013d1b valid=1 status=00000012 rc=-121 len=0"));
    assert(count(op(M11_APM_CMD_GET_CFG, 0x42D3)) == 0);
    assert(stop(&r) == 0);
    puts("PASS Run28 CFG evidence: matched zero/full-width NACK status and missing-response timeout distinguished; no amp on error");
    start(&r, (peer_cfg){0});
    uint32_t st = 123;
    bool valid = true;
    uint32_t cfg[8] = {0, 0, 0, 16};
    assert(m11_custodian_cfg_observed(&r.cust, 0, 0x428f, M11_APM_CMD_SET_CFG, cfg, sizeof cfg,
                                      ms(), NULL, 0, NULL, NULL, &st, &valid) == -EPROTO);
    assert(!valid && st == 0); /* admission rejection clears stale caller evidence */
    r.eng.transport.poll_read_fn = read_remote_errno;
    st = 123; valid = true;
    assert(m11_gpr_engine_transact_observed(&r.eng, 0x428f, M11_APM_CMD_SET_CFG, cfg, sizeof cfg,
                                           300, &st, &valid, NULL, 0, NULL) == -EREMOTEIO);
    assert(!valid && st == 0); /* same errno as a DSP NACK, different provenance */
    assert(stop(&r) == 0);
    puts("PASS Run28 status provenance: admission error and transport EREMOTEIO never acquire valid DSP status");
    puts("PASS speaker session (stand-ins: real custodian, manager, engine and journal; ALSA fixture)");
    return 0;
}
