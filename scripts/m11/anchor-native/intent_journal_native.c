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
        return -EPERM; /* CP2 post-MAP hold: no UNMAP ever leaves PID1 (no record, no TX) */
    case M11_APM_CMD_GET_SPF_STATE:
    case M11_APM_CMD_GRAPH_OPEN: case M11_APM_CMD_GRAPH_PREPARE: case M11_APM_CMD_GRAPH_START:
    case M11_APM_CMD_GRAPH_STOP: case M11_APM_CMD_GRAPH_CLOSE:
    case M11_APM_CMD_SET_CFG: case M11_APM_CMD_GET_CFG:
        snprintf(tail, sizeof tail, " pl=%zu", pll);
        break;
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
    if ((h.opcode == M11_APM_CMD_SHARED_MEM_MAP_REGIONS && !l->boot->dsp_map_attempted) ||
        (h.opcode == M11_APM_CMD_SHARED_MEM_UNMAP_REGIONS && !l->boot->dsp_unmap_attempted)) {
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
