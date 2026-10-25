/* Run3 evidence: QCA unregister can spend 80s in power_up_complete alone.
 * Matched CNSS source also permits 60s recovery wait, followed by an
 * unkillable synchronous event. The extra 40s is an observation allowance,
 * NOT a claim that event work / module_exit is bounded. No force or retry. */
#ifndef M12_RETIREMENT_POLICY_H
#define M12_RETIREMENT_POLICY_H
#include <string.h>
static unsigned m12_retirement_budget(const char *registered_name) {
    return !strcmp(registered_name,"qca6490") ? 180000u : 60000u;
}
#endif
