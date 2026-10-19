/* P4: the native custodian PID1 binary (docs/m11-argon-p4-assembly.md). The P4 environment phase
 * (Run23's pre-owned path: prepare, journal, PD locator and kmsg relay helpers, ADSP and USB start,
 * amplifier gate, endpoint/ION metadata), then the P3 entry with the helpers handed to its
 * Run23-style teardown. Never part of a candidate by itself; CI links it and checks that it refuses
 * to act outside PID1. */
#ifndef M11_CUSTODIAN_NATIVE
#error "custodian_entry_main requires the reviewed M11_CUSTODIAN_NATIVE build"
#endif
#include "custodian_entry_native.h"
#include "p4_env_native.h"
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

static m11_entry entry;
static m11_p4_env env;

static void hold(const char *why, int step, int rc) __attribute__((noreturn));
static void hold(const char *why, int step, int rc) {
    char b[160];
    int n = snprintf(b, sizeof b, "<3>M11P4 v=1 pid1 hold: %s step=%d rc=%d\n", why, step, rc);
    int fd = open("/dev/kmsg", O_WRONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (fd >= 0 && n > 0 && (size_t)n < sizeof b) { ssize_t w = write(fd, b, (size_t)n); (void)w; }
    for (;;) pause(); /* Run23: an environment failure holds; nothing audio was opened */
}

int main(int argc, char **argv) {
    (void)argv;
    if (getpid() != 1 || argc != 1) return 2; /* safe CI execution: never acts outside PID1 */
    umask(077);
    m11_entry_config c = m11_entry_config_default();
    m11_p4_env_config ec = m11_p4_env_config_default(&c.boot);
    int step = 0, rc = m11_p4_env_run(&env, &ec, &step);
    if (rc) hold("environment phase failed", step, rc);
    c.helper_pids[0] = env.locator;
    c.helper_pids[1] = env.relay;
    (void)m11_entry_run(&entry, &c);
    hold("entry returned", 0, 0); /* only reached if an end returned: PID1 holds everything it has */
}
