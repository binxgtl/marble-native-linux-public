/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef M12_CBC_EVIDENCE_H
#define M12_CBC_EVIDENCE_H
#include "../next/bootstrap-policy.h"
struct m12_golden_scope { int device,firmware,bdf,closure,trace,operator_authorized; };
struct m12_cbc_evidence { unsigned start,done,completed,mission,bdf,capability,firmware; int fault; enum m12_cal_requirement requirement; };
int m12_golden_admitted(const struct m12_caldb *,const struct m12_bootstrap_facts *,const struct m12_golden_scope *);
int m12_cbc_line(struct m12_cbc_evidence *,const char *);
int m12_cbc_ready(const struct m12_cbc_evidence *,int owner_idle,int verified_seed);
#endif
