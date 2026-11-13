/* M19 R6: Wi-Fi inside the Ubuntu session (docs/m19-r6.md). marble-wifi.service runs m19-wifi once, as root,
 * after T9-wifi staged the WLAN modules, the CNSS daemon and the firmware into RAM. It repeats M12 Run9 to Run11's
 * proven bring-up order, then hands the interface to NetworkManager and stays as the CNSS daemon's owner. */
#ifndef M19_WIFI_H
#define M19_WIFI_H

struct m19_wifi_config {
    /* inputs staged by T9-wifi */
    const char *stage;        /* /run/m19/wifi.stage: "staged" */
    const char *helper;       /* /run/m19/wifi/m19-audio */
    const char *list;         /* /run/m19/wifi/modules.list */
    const char *modules;      /* /run/m19/wifi/modules */
    const char *cnssd;        /* /run/m19/wifi/m12-cnssd */
    const char *systemctl;    /* /usr/bin/systemctl */
    const char *nm_unit;      /* NetworkManager.service */
    /* outputs */
    const char *started;      /* /run/m19/wifi.started: O_EXCL, one run a boot */
    const char *result;       /* /run/m19/wifi.result: "ready IFACE", "failed STEP RC", "skipped REASON" or "fault owner" */
    const char *report;       /* /run/m19/wifi.report: key=value lines for the reporter */
    const char *ready;        /* /run/m19/wifi.ready: NetworkManager's ConditionPathExists */
    /* the kernel */
    const char *cmdline;      /* /proc/cmdline */
    const char *proc_modules; /* /proc/modules */
    const char *hwid;         /* /sys/module/hwid/parameters */
    const char *fw_path;      /* /sys/module/firmware_class/parameters/path */
    const char *fw_want;      /* /run/m19/firmware */
    const char *pci;          /* /sys/bus/pci/devices */
    const char *platform;     /* /sys/bus/platform/devices/b0000000.qcom,cnss-qca6490 */
    const char *mhi;          /* /sys/bus/mhi/devices */
    const char *net;          /* /sys/class/net */
    const char *fs_ready;     /* /sys/kernel/cnss/fs_ready */
    const char *kmsg;         /* /dev/kmsg */
    /* time, in ms */
    unsigned load_ms, settle_ms, owner_ms, fs_ready_ms, cbc_ms, iface_ms, command_ms, pump_ms;
    /* m12-cnssd runs only as init's child (getppid() == 1, M12 ran it under its own PID 1): an intermediate child
     * forks it and exits, and it execs once init adopted it, within adopt_ms. Production: init_pid 1, adopt_ms 2000,
     * middle_hold_ms 0. Tests: their own subreaper as init, and a held intermediate so an exec before adoption shows. */
    int init_pid;
    unsigned adopt_ms, middle_hold_ms;
    /* 0 in production: supervise the daemon forever. Tests: return this many ms after the end. */
    unsigned return_after_ms;
    int require_root; /* production 1 */
};

struct m19_wifi_config m19_wifi_config_default(void);
/* The bring-up. In production it never returns once it has begun (it stays as the daemon's owner); 2 when it
 * refused before touching anything. Tests return through return_after_ms: 0 ready, 1 otherwise. */
int m19_wifi_run(const struct m19_wifi_config *c);

/* One /dev/kmsg record line "PRI,SEQ,TS,FLAGS;MESSAGE": 0 with its sequence and message, 1 for a continuation
 * line (it starts with a space), -1 when malformed. */
int m19_wifi_kmsg_record(const char *line, unsigned long long *seq, const char **message);

#endif
