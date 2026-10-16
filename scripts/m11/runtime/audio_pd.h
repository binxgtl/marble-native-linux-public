/* Native engineering only. QMI listener registration is an active operation.
 * No PD restart, ADSP boot, graph, PCM, calibration or amplifier operation. */
#ifndef M11_AUDIO_PD_H
#define M11_AUDIO_PD_H
#include <stddef.h>
#include <stdint.h>

#define M11_PD_PATH "msm/adsp/audio_pd"
#define M11_PD_INSTANCE 74u /* Pinned stock adspua.jsn, NOT a QRTR node/port. */
#define M11_PD_UP 0x1fffffffu
#define M11_PD_DOWN 0x0fffffffu
#define M11_PD_WIRE_MAX 128u
#define M11_PD_RECORDS 96u
enum m11_pd_phase { M11_PD_DISCOVERY, M11_PD_REGISTERING, M11_PD_WAIT_UP,
    M11_PD_READY, M11_PD_INVALID, M11_PD_UNREGISTERING, M11_PD_STOPPED };
enum m11_pd_fault { M11_PD_OK, M11_PD_MALFORMED, M11_PD_PEER_LOST,
    M11_PD_NOT_UP, M11_PD_DEADLINE, M11_PD_IO, M11_PD_OVERFLOW,
    M11_PD_UNRESOLVED, M11_PD_CLOCK };
struct m11_pd_record {
    uint64_t ns;
    uint32_t node, port, size, tx;
    int rc; /* RX length; TX0 means full datagram, negative errno otherwise. */
    unsigned char bytes[M11_PD_WIRE_MAX];
};
/* Internal codec state, exposed for offline fixture tests, not an UP assertion
 * accepted by the production query API. All deadlines are monotonic. */
struct m11_pd {
    enum m11_pd_phase phase;
    enum m11_pd_fault fault;
    uint32_t local_node, local_port, node, port, state;
    uint16_t next_txn, register_txn, ack_txn, indication_txn;
    uint32_t indication_state;
    int peer, registered, saw_indication, ever_ready, invalid, resources_busy;
    int ack_deferred, stopping, unregister_sent, unregister_ok, lookup_removed;
    uint64_t now, deadline, register_deadline, ack_deadline;
    unsigned int count;
    int truncated;
    struct m11_pd_record records[M11_PD_RECORDS];
    void *context;
    int (*send)(void *, uint32_t, uint32_t, const void *, size_t);
};
int m11_pd_begin(struct m11_pd *, uint32_t, uint32_t, uint64_t, uint64_t,
                 int (*)(void *,uint32_t,uint32_t,const void *,size_t), void *);
int m11_pd_receive(struct m11_pd *, uint32_t, uint32_t, const void *, size_t, uint64_t);
int m11_pd_tick(struct m11_pd *, uint64_t);
void m11_pd_fail(struct m11_pd *, enum m11_pd_fault);
int m11_pd_resources_released(struct m11_pd *);
int m11_pd_stop(struct m11_pd *, uint64_t, uint64_t);
#endif
