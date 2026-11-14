/* SPDX-License-Identifier: GPL-2.0-only
 * RAM-only CNSS platform IPC protocol. No firmware/calibration actuator.
 * Descriptor contract independently recovered from the exact stock module.
 */
#ifndef M12_CALDB_H
#define M12_CALDB_H
#include <stddef.h>
#include <stdint.h>
#define M12_CALDB_MAX (32u*1024u*1024u)
#define M12_CALDB_SEGMENT 61440u
#define M12_CALDB_WIRE 65542u
#define M12_CNSS_SERVICE 0x42eu
#define M12_CNSS_VERSION 1u
#define M12_CNSS_INSTANCE 0u
enum m12_caldb_phase { M12_DB_OFF, M12_DB_REGISTER, M12_DB_SETUP,
    M12_DB_IDLE, M12_DB_DOWNLOAD, M12_DB_UPLOAD, M12_DB_FAILED };
struct m12_caldb {
    enum m12_caldb_phase phase;
    uint32_t node, port, file_id, segment, total, offset, size;
    uint16_t txn, waiting_msg, qmi_result, qmi_error;
    uint64_t deadline, file_deadline, driver_status, last_tick;
    unsigned char *ram;
    size_t capacity;
    int error, registered, setup_ack, ram_valid, pending_upload;
};
struct m12_caldb_packet { unsigned char bytes[M12_CALDB_WIRE]; size_t size; };
/* Output is a single QMI request; no retransmission is ever produced.
 * Socket/peer census, deadlines, transport errors and resource ownership
 * remain caller responsibilities. now_ms must be monotonic and nonzero. */
int m12_caldb_begin(struct m12_caldb *, unsigned char *, size_t,
    uint32_t node, uint32_t port, uint64_t now_ms, struct m12_caldb_packet *);
int m12_caldb_receive(struct m12_caldb *, uint32_t node, uint32_t port,
    const unsigned char *, size_t, uint64_t now_ms, struct m12_caldb_packet *);
int m12_caldb_tick(struct m12_caldb *, uint64_t now_ms);
/* Caller must independently validate a read-only, device-specific snapshot.
 * No API here locates, reads, overwrites or guesses a factory file. */
int m12_caldb_seed(struct m12_caldb *,const unsigned char *,size_t);
void m12_caldb_disconnect(struct m12_caldb *);
int m12_caldb_owned(const struct m12_caldb *);
#endif
