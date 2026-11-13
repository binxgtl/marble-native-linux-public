/* M19 R6: m19-wifi's entry. Production takes no argument and the fixed paths of wifi.c. The test build
 * (M19_WIFI_TEST) roots every path under $M19_WIFI_ROOT and takes short timings from the environment. */
#include "wifi.h"

#include <stdio.h>
#include <stdlib.h>

#ifdef M19_WIFI_TEST
#include <dirent.h>
#include <errno.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <linux/nl80211.h>
#include <stdint.h>
#include <string.h>

static const char *net_dir;

/* A fake interface's nl80211 type, from net/NAME/m19-iftype beside its ifindex: station, p2p-device or nan. */
static int fake_iftype(uint32_t index)
{
    DIR *directory = opendir(net_dir);
    if (!directory)
        return -1;
    int type = -1;
    struct dirent *entry;
    while ((entry = readdir(directory))) {
        char path[4096], text[32] = "";
        if (entry->d_name[0] == '.')
            continue;
        snprintf(path, sizeof(path), "%s/%s/ifindex", net_dir, entry->d_name);
        FILE *file = fopen(path, "r");
        if (!file)
            continue;
        unsigned long value = 0;
        int scanned = fscanf(file, "%lu", &value);
        fclose(file);
        if (scanned != 1 || value != index)
            continue;
        snprintf(path, sizeof(path), "%s/%s/m19-iftype", net_dir, entry->d_name);
        file = fopen(path, "r");
        if (!file)
            break;
        if (!fgets(text, sizeof(text), file))
            text[0] = 0;
        fclose(file);
        type = !strcmp(text, "station\n") ? NL80211_IFTYPE_STATION : !strcmp(text, "p2p-device\n") ? NL80211_IFTYPE_P2P_DEVICE
               : !strcmp(text, "nan\n")   ? NL80211_IFTYPE_NAN
                                           : -1;
        break;
    }
    closedir(directory);
    return type;
}

static size_t put_attr(unsigned char *at, uint16_t type, const void *value, size_t size)
{
    struct nlattr a = {.nla_len = (uint16_t)(sizeof(a) + size), .nla_type = type};
    memcpy(at, &a, sizeof(a));
    memcpy(at + sizeof(a), value, size);
    return (sizeof(a) + size + 3) & ~(size_t)3;
}

/* The test's nl80211, a generic netlink peer that answers m19-wifi's two requests from the fake sysfs.
 * M19_FAKE_NL: nofamily (no nl80211), error (every interface query refused), wrong-index, no-wiphy. */
static int fake_netlink(const void *request, size_t length, unsigned char *reply, size_t room)
{
    const char *mode = getenv("M19_FAKE_NL") ? getenv("M19_FAKE_NL") : "";
    const unsigned char *in = request;
    struct nlmsghdr q;
    struct genlmsghdr g;
    struct nlattr a;
    if (length < sizeof(q) + sizeof(g) + sizeof(a))
        return -EINVAL;
    memcpy(&q, in, sizeof(q));
    memcpy(&g, in + sizeof(q), sizeof(g));
    memcpy(&a, in + sizeof(q) + sizeof(g), sizeof(a));
    const unsigned char *value = in + sizeof(q) + sizeof(g) + sizeof(a);
    if (q.nlmsg_len != length || !(q.nlmsg_flags & NLM_F_REQUEST) || a.nla_len < sizeof(a) || sizeof(q) + sizeof(g) + a.nla_len > length)
        return -EINVAL;
    unsigned char out[256];
    memset(out, 0, sizeof(out));
    struct nlmsghdr h = {.nlmsg_seq = q.nlmsg_seq};
    struct genlmsghdr r = {.version = 1};
    size_t at = sizeof(h);
    int error = 0;
    const uint16_t family = 0x1c;
    if (q.nlmsg_type == GENL_ID_CTRL && g.cmd == CTRL_CMD_GETFAMILY && a.nla_type == CTRL_ATTR_FAMILY_NAME &&
        a.nla_len == sizeof(a) + 8 && !memcmp(value, "nl80211", 8)) {
        if (!strcmp(mode, "nofamily")) {
            error = -ENOENT;
        } else {
            h.nlmsg_type = GENL_ID_CTRL;
            r.cmd = CTRL_CMD_NEWFAMILY;
            memcpy(out + at, &r, sizeof(r));
            at += sizeof(r);
            at += put_attr(out + at, CTRL_ATTR_FAMILY_ID, &family, sizeof(family));
        }
    } else if (q.nlmsg_type == family && g.cmd == NL80211_CMD_GET_INTERFACE && a.nla_type == NL80211_ATTR_IFINDEX &&
               a.nla_len == sizeof(a) + 4) {
        uint32_t index;
        memcpy(&index, value, sizeof(index));
        int type = fake_iftype(index);
        if (type < 0 || !strcmp(mode, "error")) {
            error = -ENODEV;
        } else {
            h.nlmsg_type = family;
            r.cmd = NL80211_CMD_NEW_INTERFACE;
            memcpy(out + at, &r, sizeof(r));
            at += sizeof(r);
            uint32_t got = index + !strcmp(mode, "wrong-index"), wiphy = !strcmp(mode, "no-wiphy") ? UINT32_MAX : 0, kind = (uint32_t)type;
            at += put_attr(out + at, NL80211_ATTR_WIPHY, &wiphy, sizeof(wiphy));
            at += put_attr(out + at, NL80211_ATTR_IFINDEX, &got, sizeof(got));
            at += put_attr(out + at, NL80211_ATTR_IFTYPE, &kind, sizeof(kind));
        }
    } else {
        error = -EOPNOTSUPP;
    }
    if (error) {
        struct nlmsgerr e = {.error = error, .msg = q};
        h.nlmsg_type = NLMSG_ERROR;
        memcpy(out + sizeof(h), &e, sizeof(e));
        at = sizeof(h) + sizeof(e);
    }
    h.nlmsg_len = (uint32_t)at;
    memcpy(out, &h, sizeof(h));
    if (at > room)
        return -EMSGSIZE;
    memcpy(reply, out, at);
    return (int)at;
}

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
    c.return_after_ms = env_ms("M19_WIFI_RETURN_MS", 300);
    c.require_root = 0;
    net_dir = c.net;
    c.netlink = fake_netlink;
#endif
    return m19_wifi_run(&c);
}
