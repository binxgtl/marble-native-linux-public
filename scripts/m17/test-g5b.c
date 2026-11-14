/* M17 G5b: the speaker protection probe's requests, reply check and log (awprobe.h), on synthetic replies. No device. */
#define _GNU_SOURCE
#include "awprobe.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures;
#define CHECK(cond)                                                                                                    \
    do {                                                                                                               \
        if (!(cond)) {                                                                                                 \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond);                                   \
            failures++;                                                                                                \
        }                                                                                                              \
    } while (0)

static uint32_t word(const uint8_t *p, unsigned i) {
    uint32_t v;
    memcpy(&v, p + 4u * i, 4);
    return v;
}

static void test_requests(void) {
    uint8_t cmd[M17_AW_CMD_BYTES];
    memset(cmd, 0xa5, sizeof cmd);
    CHECK(m17_aw_status_cmd(cmd) == 56);
    /* apm_cmd_header_t: in band (no address, no map handle), then 40 payload bytes */
    static const uint32_t want_cmd[14] = {0, 0, 0, 40, 0x42D3, 0x10013D2A, 24, 0, 1, 7, 1, 0, 0, 0};
    for (unsigned i = 0; i < 14; i++)
        CHECK(word(cmd, i) == want_cmd[i]);
    uint8_t req[M17_AW_REQ_BYTES];
    memset(req, 0xa5, sizeof req);
    CHECK(m17_aw_status_req(req) == 64);
    static const uint32_t want_req[16] = {0, 0, 0, 48, 0x42D3, 0x10013D2A, 32, 0};
    for (unsigned i = 0; i < 16; i++)
        CHECK(word(req, i) == want_req[i]);
}

static size_t reply(uint8_t *out, uint32_t status, uint32_t iid, uint32_t param, uint32_t size, uint32_t error) {
    const uint32_t head[5] = {status, iid, param, size, error};
    /* speaker 0: Re 26099 Q12 (6371 mOhm), 35; speaker 1: Re 28684 Q12 (7002 mOhm), 36 */
    const uint32_t data[8] = {26099, 11, 35, 12, 28684, 13, 36, 14};
    memcpy(out, head, sizeof head);
    memcpy(out + sizeof head, data, sizeof data);
    return sizeof head + sizeof data;
}

static void test_parse(void) {
    uint8_t rsp[64];
    struct m17_aw_status st;
    size_t n = reply(rsp, 0, 0x42D3, 0x10013D2A, 32, 0);
    CHECK(n == M17_AW_RSP_BYTES);
    CHECK(m17_aw_status_parse(rsp, n, &st) == 0);
    CHECK(st.re_mohm[0] == 6371 && st.re_mohm[1] == 7002 && st.te[0] == 35 && st.te[1] == 36);
    CHECK(st.raw[1] == 11 && st.raw[3] == 12 && st.raw[5] == 13 && st.raw[7] == 14);
    /* a larger parameter is accepted; only the first 32 bytes are read */
    uint8_t big[96] = {0};
    memcpy(big, rsp, n);
    uint32_t size = 40;
    memcpy(big + 12, &size, 4);
    CHECK(m17_aw_status_parse(big, n + 8, &st) == 0 && st.re_mohm[1] == 7002);
    /* anything else is refused, and nothing of it is kept */
    CHECK(m17_aw_status_parse(rsp, n - 1, &st) == -EPROTO && st.re_mohm[0] == 0);
    n = reply(rsp, 1, 0x42D3, 0x10013D2A, 32, 0);
    CHECK(m17_aw_status_parse(rsp, n, &st) == -EPROTO);
    n = reply(rsp, 0, 0x42D4, 0x10013D2A, 32, 0);
    CHECK(m17_aw_status_parse(rsp, n, &st) == -EPROTO);
    n = reply(rsp, 0, 0x42D3, 0x10013D2B, 32, 0);
    CHECK(m17_aw_status_parse(rsp, n, &st) == -EPROTO);
    n = reply(rsp, 0, 0x42D3, 0x10013D2A, 31, 0);
    CHECK(m17_aw_status_parse(rsp, n, &st) == -EPROTO);
    n = reply(rsp, 0, 0x42D3, 0x10013D2A, 32, 5);
    CHECK(m17_aw_status_parse(rsp, n, &st) == -EPROTO);
    CHECK(m17_aw_status_parse(NULL, 64, &st) == -EPROTO);
    /* a negative raw value stays signed */
    n = reply(rsp, 0, 0x42D3, 0x10013D2A, 32, 0);
    int32_t minus = -4096;
    memcpy(rsp + 20, &minus, 4);
    CHECK(m17_aw_status_parse(rsp, n, &st) == 0 && st.re_mohm[0] == -1000);
}

static void test_log(void) {
    char dir[256], path[300], older[310], link[310], text[2048];
    snprintf(dir, sizeof dir, "%s/m17-g5b-%d", getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp", (int)getpid());
    CHECK(!mkdir(dir, 0700));
    snprintf(path, sizeof path, "%s/m17-aw.log", dir);
    snprintf(older, sizeof older, "%s.1", path);
    struct m17_aw_status st;
    uint8_t rsp[64];
    CHECK(m17_aw_status_parse(rsp, reply(rsp, 0, 0x42D3, 0x10013D2A, 32, 0), &st) == 0);
    CHECK(m17_aw_status_log(path, 4096, &st, 1, 10362, 0, 0) == 0);
    FILE *f = fopen(path, "r");
    CHECK(f && fgets(text, sizeof text, f));
    if (f) fclose(f);
    CHECK(strstr(text, " re=6371,7002 te=35,36 raw=000065f3,0000000b,00000023,0000000c,0000700c,0000000d,00000024,0000000e "
                       "amp=1 peak=10362 rc=0 status=00000000\n") != NULL);
    struct stat s;
    CHECK(!stat(path, &s) && (s.st_mode & 0777) == 0600);
    /* a failed probe is a line too, its values zero */
    struct m17_aw_status none;
    memset(&none, 0, sizeof none);
    CHECK(m17_aw_status_log(path, 4096, &none, 1, 0, -EREMOTEIO, 0x12) == 0);
    /* at the limit the file moves to .1 */
    CHECK(m17_aw_status_log(path, 100, &st, 0, 0, 0, 0) == 0);
    CHECK(!stat(older, &s) && s.st_size > 100 && !stat(path, &s) && s.st_size < 200);
    /* never through a link */
    snprintf(link, sizeof link, "%s/link.log", dir);
    CHECK(!symlink(path, link) && m17_aw_status_log(link, 4096, &st, 0, 0, 0, 0) == -EINVAL);
    CHECK(m17_aw_status_log("/nonexistent-m17/x.log", 4096, &st, 0, 0, 0, 0) == -ENOENT);
    char cmd[400];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", dir);
    CHECK(!system(cmd));
}

int main(void) {
    test_requests();
    test_parse();
    test_log();
    if (failures) {
        fprintf(stderr, "M17 G5b tests: %d failed\n", failures);
        return 1;
    }
    printf("M17 G5b protection probe PASS\n");
    return 0;
}
