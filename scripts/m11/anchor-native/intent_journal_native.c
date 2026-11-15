/* G7 intent journal — see intent_journal_native.h. */
#define _GNU_SOURCE
#include "intent_journal_native.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int m11_intent_format(char *buf, size_t cap, uint64_t epoch, uint32_t seq, const uint8_t *pkt, size_t len) {
    m11_gpr_hdr_t h; const uint8_t *pl; size_t pll;
    if (!buf || !pkt || m11_gpr_validate_packet(pkt, len, &h, &pl, &pll) < 0) return -EBADMSG;
    char tail[96] = "";
    switch (h.opcode) {
    case M11_APM_CMD_SHARED_MEM_MAP_REGIONS: {
        m11_apm_cmd_shared_mem_map_regions_t c;
        if (pll != sizeof c) return -EBADMSG;
        memcpy(&c, pl, sizeof c);
        snprintf(tail, sizeof tail, " fd=%u msw=%u bytes=%u pool=%u regions=%u flags=%x",
                 c.shm_addr_lsw, c.shm_addr_msw, c.mem_size_bytes, c.mem_pool_id, c.num_regions, c.property_flag);
        break;
    }
    case M11_APM_CMD_SHARED_MEM_UNMAP_REGIONS:
        return -EPERM; /* CP2 post-MAP hold L2: no UNMAP is journaled (no record, no TX through the journal) */
    case M11_APM_CMD_GET_SPF_STATE:
    case M11_APM_CMD_GRAPH_OPEN: case M11_APM_CMD_GRAPH_PREPARE: case M11_APM_CMD_GRAPH_START:
    case M11_APM_CMD_GRAPH_STOP: case M11_APM_CMD_GRAPH_CLOSE:
    case M11_APM_CMD_SET_CFG: case M11_APM_CMD_GET_CFG:
        snprintf(tail, sizeof tail, " pl=%zu", pll);
        break;
    case M11_DATA_CMD_WR_SH_MEM_EP_DATA_BUFFER_V2:
    case M11_DATA_CMD_RD_SH_MEM_EP_DATA_BUFFER_V2: {
        /* P5 speaker session data path: <addr lsw, addr msw, map handle, size, ...> */
        uint32_t w[4];
        if (pll != (h.opcode == M11_DATA_CMD_RD_SH_MEM_EP_DATA_BUFFER_V2 ? 32u : 44u)) return -EBADMSG;
        memcpy(w, pl, sizeof w);
        snprintf(tail, sizeof tail, " addr=%u msw=%u map=%08x bytes=%u", w[0], w[1], w[2], w[3]);
        break;
    }
    case M11_DATA_CMD_WR_SH_MEM_EP_EOS: {
        uint32_t policy;
        if (pll != sizeof policy) return -EBADMSG;
        memcpy(&policy, pl, sizeof policy);
        snprintf(tail, sizeof tail, " policy=%u", policy);
        break;
    }
    default:
        return -EPERM; /* outside the custodian's set, APM_CMD_CLOSE_ALL included */
    }
    int n = snprintf(buf, cap, "<6>M11INTENT v=1 boot=%llu seq=%u op=%08x tok=%08x cd=%u dst=%08x%s\n",
                     (unsigned long long)epoch, seq, h.opcode, h.token, (unsigned)h.client_data, h.dst_port, tail);
    if (n < 0 || (size_t)n >= cap) return -ENOSPC;
    return n;
}

static int j_open(void *user) { m11_intent_link *l = user; return l->inner.open_fn(l->inner.user); }
static int j_close(void *user, int fd) { m11_intent_link *l = user; return l->inner.close_fn(l->inner.user, fd); }
static int j_poll_read(void *user, int fd, uint8_t *buf, size_t cap, uint32_t timeout_ms) {
    m11_intent_link *l = user;
    return l->inner.poll_read_fn(l->inner.user, fd, buf, cap, timeout_ms);
}
static int j_write(void *user, int fd, const uint8_t *buf, size_t len) {
    m11_intent_link *l = user;
    char rec[M11_INTENT_RECORD_MAX];
    int n = m11_intent_format(rec, sizeof rec, l->boot->boot_epoch, l->seq + 1u, buf, len);
    if (n < 0) { l->refused++; return n == -EPERM ? -EPERM : -EINVAL; }
    m11_gpr_hdr_t h; const uint8_t *pl; size_t pll;
    (void)m11_gpr_validate_packet(buf, len, &h, &pl, &pll); /* already validated by the format */
    const int data = h.opcode == M11_DATA_CMD_WR_SH_MEM_EP_DATA_BUFFER_V2 ||
                     h.opcode == M11_DATA_CMD_RD_SH_MEM_EP_DATA_BUFFER_V2 || h.opcode == M11_DATA_CMD_WR_SH_MEM_EP_EOS;
    if ((h.opcode == M11_APM_CMD_SHARED_MEM_MAP_REGIONS && !l->boot->dsp_map_attempted) ||
        (h.opcode == M11_APM_CMD_SHARED_MEM_UNMAP_REGIONS && !l->boot->dsp_unmap_attempted) ||
        (data && !l->boot->dsp_map_attempted)) { /* a data command names mapped memory */
        l->refused++;
        return -EPERM; /* the ledger records the intent before the journal, the journal before TX */
    }
    int arc = l->sink->append_fn(l->sink->user, rec, (size_t)n);
    if (arc != 0) { l->sink_failures++; return -EIO; } /* no TX without its journal record */
    l->seq++;
    l->journaled++;
    return l->inner.write_fn(l->inner.user, fd, buf, len);
}

int m11_intent_transport(m11_intent_link *l, const m11_gpr_transport_t *inner, const m11_intent_sink *sink,
                         const m11_boot_ledger *boot, m11_gpr_transport_t *out) {
    if (!l || !inner || !inner->open_fn || !inner->close_fn || !inner->write_fn || !inner->poll_read_fn ||
        !sink || !sink->append_fn || !boot || !boot->initialized || !out) return -EINVAL;
    *l = (m11_intent_link){.inner = *inner, .sink = sink, .boot = boot};
    *out = (m11_gpr_transport_t){.open_fn = j_open, .close_fn = j_close, .write_fn = j_write,
                                 .poll_read_fn = j_poll_read, .user = l};
    return 0;
}

static int fd_append(void *user, const char *rec, size_t len) {
    m11_intent_fd_sink *s = user;
    ssize_t n;
    do n = write(s->fd, rec, len); while (n < 0 && errno == EINTR);
    if (n != (ssize_t)len) return -EIO;
    s->writes++;
    return 0;
}
int m11_intent_sink_fd(m11_intent_fd_sink *s, int fd, m11_intent_sink *out) {
    if (!s || fd < 0 || !out) return -EINVAL;
    *s = (m11_intent_fd_sink){.fd = fd};
    *out = (m11_intent_sink){.append_fn = fd_append, .user = s};
    return 0;
}

static int rot_append(void *user, const char *rec, size_t len) {
    m11_intent_rotating_sink *s = user;
    if (s->fd < 0) return -EBADF;
    if (s->on_fd >= s->per_fd) {
        /* a fresh open file: /dev/kmsg rate-limits each open file to a burst of 10 records */
        int nfd = s->reopen_fn(s->reopen_user);
        if (nfd < 0) { s->reopen_failures++; return -EIO; }
        (void)close(s->fd);
        s->fd = nfd;
        s->on_fd = 0;
        s->reopens++;
    }
    ssize_t n;
    do n = write(s->fd, rec, len); while (n < 0 && errno == EINTR);
    if (n != (ssize_t)len) return -EIO;
    s->on_fd++;
    s->writes++;
    return 0;
}
int m11_intent_sink_rotating(m11_intent_rotating_sink *s, int fd, unsigned per_fd,
                             int (*reopen_fn)(void *), void *reopen_user, m11_intent_sink *out) {
    if (!s || fd < 0 || !per_fd || per_fd > 9u || !reopen_fn || !out) return -EINVAL;
    *s = (m11_intent_rotating_sink){.fd = fd, .per_fd = per_fd, .reopen_fn = reopen_fn, .reopen_user = reopen_user};
    *out = (m11_intent_sink){.append_fn = rot_append, .user = s};
    return 0;
}
