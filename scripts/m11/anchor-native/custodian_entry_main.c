/* Production P3: the native custodian PID1 binary (docs/m11-custodian-native-integration.md). Never
 * part of a candidate; CI links it and checks that it refuses to act outside PID1. */
#ifndef M11_CUSTODIAN_NATIVE
#error "custodian_entry_main requires the reviewed M11_CUSTODIAN_NATIVE build"
#endif
#include "custodian_entry_native.h"
#include <unistd.h>

static m11_entry entry;

int main(int argc, char **argv) {
    (void)argv;
    if (getpid() != 1 || argc != 1) return 2; /* safe CI execution: never acts outside PID1 */
    m11_entry_config c = m11_entry_config_default();
    (void)m11_entry_run(&entry, &c);
    for (;;) pause(); /* only reached if an end returned: PID1 holds everything it has */
}
