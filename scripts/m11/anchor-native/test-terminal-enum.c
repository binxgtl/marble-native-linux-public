/* Printed once per build mode; test.sh requires identical output (the native build defines the
 * terminal enum itself because it links no custodian). */
#include "m11_pid1_anchor.h"
#include <stdio.h>
int main(void) {
    printf("ORDERLY_SHUTDOWN=%d HOLD=%d HOLD_RECONCILE=%d RESET_RETAINING_ANCHORS=%d UNSAFE_LAST_CLOSE_OCCURRED=%d\n",
           M11_TERMINAL_ORDERLY_SHUTDOWN, M11_TERMINAL_HOLD, M11_TERMINAL_HOLD_RECONCILE,
           M11_TERMINAL_RESET_RETAINING_ANCHORS, M11_TERMINAL_UNSAFE_LAST_CLOSE_OCCURRED);
    return 0;
}
