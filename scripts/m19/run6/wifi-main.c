/* M19 R6: m19-wifi's entry. Production takes no argument and the fixed paths of wifi.c. The test build
 * (M19_WIFI_TEST) roots every path under $M19_WIFI_ROOT and takes short timings from the environment. */
#include "wifi.h"

#include <stdio.h>
#include <stdlib.h>

#ifdef M19_WIFI_TEST
static const char *under(const char *root, const char *path)
{
    size_t n = snprintf(NULL, 0, "%s%s", root, path) + 1;
    char *joined = malloc(n);
    if (!joined)
        exit(3);
    snprintf(joined, n, "%s%s", root, path);
    return joined;
}

static unsigned env_ms(const char *name, unsigned fallback)
{
    const char *text = getenv(name);
    return text ? (unsigned)strtoul(text, NULL, 10) : fallback;
}
#endif

int main(int argc, char **argv)
{
    (void)argv;
    if (argc != 1)
        return 2;
    struct m19_wifi_config c = m19_wifi_config_default();
#ifdef M19_WIFI_TEST
    const char *root = getenv("M19_WIFI_ROOT");
    if (!root)
        return 2;
    const char **paths[] = {&c.stage, &c.helper, &c.list, &c.modules, &c.cnssd, &c.started, &c.result, &c.report, &c.ready, &c.cmdline,
                            &c.proc_modules, &c.hwid, &c.fw_path, &c.pci, &c.platform, &c.mhi, &c.net, &c.fs_ready, &c.kmsg};
    for (size_t i = 0; i < sizeof(paths) / sizeof(*paths); i++)
        *paths[i] = under(root, *paths[i]);
    c.systemctl = under(root, "/usr/bin/systemctl");
    c.load_ms = env_ms("M19_WIFI_LOAD_MS", 10000);
    c.settle_ms = env_ms("M19_WIFI_SETTLE_MS", 50);
    c.owner_ms = env_ms("M19_WIFI_OWNER_MS", 3000);
    c.fs_ready_ms = env_ms("M19_WIFI_FS_READY_MS", 3000);
    c.cbc_ms = env_ms("M19_WIFI_CBC_MS", 3000);
    c.iface_ms = env_ms("M19_WIFI_IFACE_MS", 1500);
    c.command_ms = env_ms("M19_WIFI_COMMAND_MS", 3000);
    c.pump_ms = 5;
    /* The test is its own init: a subreaper that adopts the daemon. */
    c.init_pid = (int)env_ms("M19_WIFI_INIT_PID", 1);
    c.adopt_ms = env_ms("M19_WIFI_ADOPT_MS", 2000);
    c.middle_hold_ms = env_ms("M19_WIFI_MIDDLE_MS", 0);
    c.return_after_ms = env_ms("M19_WIFI_RETURN_MS", 300);
    c.require_root = 0;
#endif
    return m19_wifi_run(&c);
}
