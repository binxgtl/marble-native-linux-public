/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef M12_CNSSD_H
#define M12_CNSSD_H
#include "caldb.h"
#define M12_OWNER_MAGIC 0x4d313243u
#define M12_OWNER_VERSION 1u
enum m12_owner_event { M12_DISCOVERY=1, M12_RX, M12_TX, M12_READY,
    M12_POISON, M12_STOP_DENIED, M12_RETIRED, M12_STATE };
/* Private same-host SOCK_SEQPACKET ABI, not a USB or QRTR wire structure.
 * Zero-initialized; no seed payload, pathname or credentials in evidence. */
struct m12_owner_record {
    uint32_t magic, version, sequence, event, phase, node, port, size;
    int32_t rc;
    uint32_t qmi_result, qmi_error, seed_verified, ram_valid;
    uint32_t transaction, waiting_message, segment, offset;
    uint64_t driver_status;
    unsigned char seed_sha256[32], source_evidence_sha256[32];
};
struct m12_owner_stop {
    uint32_t magic, version, qca_retired, cnss_retired;
    uint32_t unresolved_child, transfer_pending;
};
enum m12_input_kind { M12_INPUT_QRTR=1, M12_INPUT_STOP };
struct m12_input {
    enum m12_input_kind kind;
    uint32_t node, port;
    size_t size;
    unsigned char bytes[M12_CALDB_WIRE];
    struct m12_owner_stop stop;
};
struct m12_daemon {
    struct m12_caldb db;
    uint32_t local_node, peer_port, census, sequence;
    uint64_t discovery_deadline;
    int discovered, poisoned, error, seed_verified;
    unsigned char seed_sha256[32], source_evidence_sha256[32];
};
/* I/O boundary permits the SAME event loop to run against synthetic QRTR.
 * wait: 1 input, 0 elapsed, negative errno. faulted disables QRTR reads;
 * keep supervisor/owner alive until explicit consumer-retirement proof.
 * seed: optional immutable snapshot copy after INIT_SETUP; 0 no seed,
 * 1 verified seed, negative verification error. */
struct m12_daemon_io {
    void *ctx;
    uint64_t (*now)(void *);
    int (*wait)(void *, unsigned ms, int faulted, struct m12_input *);
    int (*send)(void *, uint32_t, uint32_t, const void *, size_t);
    int (*record)(void *, const struct m12_owner_record *);
    int (*seed)(void *, unsigned char *, size_t, size_t *, unsigned char[32], unsigned char[32]);
};
int m12_cnssd_run(struct m12_daemon *, const struct m12_daemon_io *,
                 uint32_t local_node, unsigned char *ram, size_t capacity);
/* Linux immutable RAM seed: read-only sealed memfd, exact size/content hash,
 * nonzero provenance evidence digest supplied by the trusted supervisor.
 * Hash binding is not independent proof that a file fits this device. */
int m12_cnssd_seed_fd(int fd, size_t expected_size,
                     const unsigned char expected_sha256[32],
                     int source_evidence_fd,
                     const unsigned char source_evidence_sha256[32],
                     unsigned char *ram, size_t capacity);
#endif
