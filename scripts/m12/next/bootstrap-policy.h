/* Explicit admission contract, not a device actuator. None of these facts
 * may be inferred from a QMI registration ACK or init driver_status alone. */
#ifndef M12_BOOTSTRAP_POLICY_H
#define M12_BOOTSTRAP_POLICY_H
#include "caldb.h"
enum m12_cal_requirement { M12_CAL_UNKNOWN, M12_CAL_REQUIRED, M12_CAL_NOT_REQUIRED };
struct m12_bootstrap_facts {
    int exact_stock_ipc_contract, unique_local_service, inherited_owned_transport;
    int logger_live, host_prequery_ack, owner_live;
    int wifi_cbc_authorized, read_only_seed_verified;
    enum m12_cal_requirement bdf_cal_requirement;
};
static inline int m12_cbc_admitted(const struct m12_caldb *s,const struct m12_bootstrap_facts *f) {
    return m12_caldb_owned(s) && f->exact_stock_ipc_contract==1 &&
        f->unique_local_service==1 && f->inherited_owned_transport==1 &&
        f->logger_live==1 && f->host_prequery_ack==1 && f->owner_live==1 &&
        f->wifi_cbc_authorized==1 &&
        (f->bdf_cal_requirement==M12_CAL_NOT_REQUIRED ||
         ((f->bdf_cal_requirement==M12_CAL_REQUIRED || f->bdf_cal_requirement==M12_CAL_UNKNOWN) &&
          f->read_only_seed_verified==1 && s->ram_valid && s->size));
}
/* The owner must remain alive until ALL CNSS/QCA consumers finish retiring.
 * PID1 may not stop it merely because a readiness deadline expired. */
static inline int m12_caldb_stop_admitted(int qca_retired,int cnss_retired,
                                  int unresolved_child,int transfer_pending) {
    return qca_retired==1 && cnss_retired==1 && unresolved_child==0 && transfer_pending==0;
}
#endif
