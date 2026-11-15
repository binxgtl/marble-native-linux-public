/* M17 G5b/G5c: the speaker protection probe's requests, reply check and log, and G5c's backstop (awprobe.h), on
 * synthetic replies. No device. */
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

/* a reply with these eight data words */
static size_t reply_words(uint8_t *out, uint32_t status, uint32_t iid, uint32_t param, uint32_t size, uint32_t error,
                          const uint32_t data[8]) {
    const uint32_t head[5] = {status, iid, param, size, error};
    memcpy(out, head, sizeof head);
    memcpy(out + sizeof head, data, 32);
    return sizeof head + 32;
}

/* speaker 0: Re 26099 Q12 (6371 mOhm), 35; speaker 1: Re 28684 Q12 (7002 mOhm), 36 */
static const uint32_t LIVE[8] = {26099, 11, 35, 12, 28684, 13, 36, 14};

static size_t reply(uint8_t *out, uint32_t status, uint32_t iid, uint32_t param, uint32_t size, uint32_t error) {
    return reply_words(out, status, iid, param, size, error, LIVE);
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

static struct m17_aw_status status_of(const uint32_t data[8]) {
    uint8_t rsp[64];
    struct m17_aw_status st;
    if (m17_aw_status_parse(rsp, reply_words(rsp, 0, 0x42D3, 0x10013D2A, 32, 0, data), &st))
        failures++;
    return st;
}

/* G5b's reference reply: both words of each Re the calibration's, every temperature 25 */
static const uint32_t REF[8] = {0x65F3, 0x65F3, 25, 25, 0x700C, 0x700C, 25, 25};
/* a live reply as G5b saw (6210 / 6931 mOhm, 18 / 22) */
static const uint32_t G5B_LIVE[8] = {0x6510, 0x63C7, 18, 19, 0x6EEA, 0x6F43, 22, 22};

static void test_reference(void) {
    struct m17_aw_status st = status_of(REF);
    CHECK(m17_aw_status_is_reference(&st));
    st = status_of(G5B_LIVE);
    CHECK(!m17_aw_status_is_reference(&st));
    /* each condition matters */
    uint32_t w[8];
    memcpy(w, REF, sizeof w);
    w[1] = 0x65F4;
    st = status_of(w);
    CHECK(!m17_aw_status_is_reference(&st));
    memcpy(w, REF, sizeof w);
    w[5] = 0x700D;
    st = status_of(w);
    CHECK(!m17_aw_status_is_reference(&st));
    memcpy(w, REF, sizeof w);
    w[2] = 26;
    st = status_of(w);
    CHECK(!m17_aw_status_is_reference(&st));
    memcpy(w, REF, sizeof w);
    w[6] = 24;
    st = status_of(w);
    CHECK(!m17_aw_status_is_reference(&st));
}

static const struct m17_backstop G5C = {.te_limit = 45, .re_min = 3000, .re_max = 12000, .ref_limit = 10, .loud_peak = 3277};

static void test_backstop(void) {
    struct m17_backstop_state s = {0};
    struct m17_aw_status live = status_of(G5B_LIVE), ref = status_of(REF), none;
    memset(&none, 0, sizeof none);
    /* live, cool, in range: nothing, for as long as it lasts */
    for (int i = 0; i < 100; i++)
        CHECK(m17_backstop_step(&G5C, &s, 0, &live, 32767) == M17_DROP_NONE);
    CHECK(s.dropped == M17_DROP_NONE && s.ref_streak == 0);
    /* a failed probe drops */
    CHECK(m17_backstop_step(&G5C, &s, -EREMOTEIO, &none, 0) == M17_DROP_PROBE && s.dropped == M17_DROP_PROBE);
    /* once dropped, nothing changes it, not even a good reply */
    CHECK(m17_backstop_step(&G5C, &s, 0, &live, 0) == M17_DROP_NONE && s.dropped == M17_DROP_PROBE);
    CHECK(m17_backstop_step(&G5C, &s, 0, &live, 32767) == M17_DROP_NONE && s.dropped == M17_DROP_PROBE);
    /* temperature: 44 passes, 45 drops, on either speaker */
    for (unsigned ch = 0; ch < 2; ch++) {
        uint32_t w[8];
        memcpy(w, G5B_LIVE, sizeof w);
        w[4 * ch + 2] = 44;
        struct m17_aw_status st = status_of(w);
        memset(&s, 0, sizeof s);
        CHECK(m17_backstop_step(&G5C, &s, 0, &st, 0) == M17_DROP_NONE);
        w[4 * ch + 2] = 45;
        st = status_of(w);
        CHECK(m17_backstop_step(&G5C, &s, 0, &st, 0) == M17_DROP_TEMP && s.dropped == M17_DROP_TEMP);
    }
    /* Re: 3000 and 12000 mOhm pass, a step outside drops, on either speaker (Q12: mOhm * 4096 / 1000) */
    static const struct { uint32_t q12; enum m17_drop want; } re_cases[] = {
        {12288, M17_DROP_NONE}, {12287, M17_DROP_RE}, {49152, M17_DROP_NONE}, {49157, M17_DROP_RE}};
    for (unsigned ch = 0; ch < 2; ch++) {
        for (unsigned i = 0; i < sizeof re_cases / sizeof re_cases[0]; i++) {
            uint32_t w[8];
            memcpy(w, G5B_LIVE, sizeof w);
            w[4 * ch] = re_cases[i].q12;
            struct m17_aw_status st = status_of(w);
            memset(&s, 0, sizeof s);
            CHECK(m17_backstop_step(&G5C, &s, 0, &st, 0) == re_cases[i].want);
        }
    }
    /* blind: nine loud references pass, the tenth drops */
    memset(&s, 0, sizeof s);
    for (int i = 0; i < 9; i++)
        CHECK(m17_backstop_step(&G5C, &s, 0, &ref, 3277) == M17_DROP_NONE);
    CHECK(s.ref_streak == 9);
    CHECK(m17_backstop_step(&G5C, &s, 0, &ref, 3277) == M17_DROP_BLIND && s.dropped == M17_DROP_BLIND);
    /* quiet references neither count nor reset */
    memset(&s, 0, sizeof s);
    for (int i = 0; i < 9; i++)
        CHECK(m17_backstop_step(&G5C, &s, 0, &ref, 3277) == M17_DROP_NONE);
    for (int i = 0; i < 50; i++)
        CHECK(m17_backstop_step(&G5C, &s, 0, &ref, 3276) == M17_DROP_NONE);
    CHECK(s.ref_streak == 9);
    CHECK(m17_backstop_step(&G5C, &s, 0, &ref, 3277) == M17_DROP_BLIND);
    /* a live reply resets the streak */
    memset(&s, 0, sizeof s);
    for (int i = 0; i < 9; i++)
        CHECK(m17_backstop_step(&G5C, &s, 0, &ref, 30000) == M17_DROP_NONE);
    CHECK(m17_backstop_step(&G5C, &s, 0, &live, 30000) == M17_DROP_NONE && s.ref_streak == 0);
    for (int i = 0; i < 9; i++)
        CHECK(m17_backstop_step(&G5C, &s, 0, &ref, 30000) == M17_DROP_NONE);
    CHECK(s.dropped == M17_DROP_NONE);
    /* a reference never counts as a temperature: 25 is below any limit, and a hot reference cannot exist */
    CHECK(strcmp(m17_drop_name(M17_DROP_NONE), "none") == 0 && strcmp(m17_drop_name(M17_DROP_PROBE), "probe") == 0 &&
          strcmp(m17_drop_name(M17_DROP_TEMP), "temp") == 0 && strcmp(m17_drop_name(M17_DROP_RE), "re") == 0 &&
          strcmp(m17_drop_name(M17_DROP_BLIND), "blind") == 0);
}

static void test_valid(void) {
    struct m17_probe_config c = {.log = "/x", .period_ms = 2000, .log_limit = 1, .gain_q15 = 32768, .peak_limit = 32767,
                                 .backstop = G5C};
    CHECK(m17_backstop_valid(&c));
    struct m17_probe_config b;
    /* G5b's configuration (no gain) never plays louder */
    b = c; b.gain_q15 = 0; CHECK(!m17_backstop_valid(&b));
    b = c; b.log = NULL; CHECK(!m17_backstop_valid(&b));
    b = c; b.period_ms = 0; CHECK(!m17_backstop_valid(&b));
    b = c; b.period_ms = 5001; CHECK(!m17_backstop_valid(&b));
    b = c; b.period_ms = 5000; CHECK(m17_backstop_valid(&b));
    b = c; b.gain_q15 = 32769; CHECK(!m17_backstop_valid(&b));
    b = c; b.peak_limit = 0; CHECK(!m17_backstop_valid(&b));
    b = c; b.peak_limit = 32768; CHECK(!m17_backstop_valid(&b));
    b = c; b.backstop.te_limit = 25; CHECK(!m17_backstop_valid(&b));
    b = c; b.backstop.te_limit = 81; CHECK(!m17_backstop_valid(&b));
    b = c; b.backstop.te_limit = 80; CHECK(m17_backstop_valid(&b));
    b = c; b.backstop.re_min = 0; CHECK(!m17_backstop_valid(&b));
    b = c; b.backstop.re_max = 3000; CHECK(!m17_backstop_valid(&b));
    b = c; b.backstop.ref_limit = 0; CHECK(!m17_backstop_valid(&b));
    b = c; b.backstop.loud_peak = 0; CHECK(!m17_backstop_valid(&b));
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
    CHECK(m17_aw_status_log(path, 4096, &st, 1, 10362, 0, 0, 32768, 1, M17_DROP_NONE) == 0);
    FILE *f = fopen(path, "r");
    CHECK(f && fgets(text, sizeof text, f));
    if (f) fclose(f);
    CHECK(strstr(text, " re=6371,7002 te=35,36 raw=000065f3,0000000b,00000023,0000000c,0000700c,0000000d,00000024,0000000e "
                       "amp=1 peak=10362 rc=0 status=00000000 gain=32768 live=1 drop=none\n") != NULL);
    struct stat s;
    CHECK(!stat(path, &s) && (s.st_mode & 0777) == 0600);
    /* a failed probe is a line too, its values zero, with the drop it caused */
    struct m17_aw_status none;
    memset(&none, 0, sizeof none);
    CHECK(m17_aw_status_log(path, 4096, &none, 1, 0, -EREMOTEIO, 0x12, 10362, 0, M17_DROP_PROBE) == 0);
    f = fopen(path, "r");
    CHECK(f && fgets(text, sizeof text, f) && fgets(text, sizeof text, f));
    if (f) fclose(f);
    CHECK(strstr(text, " rc=-121 status=00000012 gain=10362 live=0 drop=probe\n") != NULL);
    /* at the limit the file moves to .1 */
    CHECK(m17_aw_status_log(path, 100, &st, 0, 0, 0, 0, 10362, 1, M17_DROP_TEMP) == 0);
    CHECK(!stat(older, &s) && s.st_size > 100 && !stat(path, &s) && s.st_size < 220);
    /* never through a link */
    snprintf(link, sizeof link, "%s/link.log", dir);
    CHECK(!symlink(path, link) && m17_aw_status_log(link, 4096, &st, 0, 0, 0, 0, 0, 0, M17_DROP_NONE) == -EINVAL);
    CHECK(m17_aw_status_log("/nonexistent-m17/x.log", 4096, &st, 0, 0, 0, 0, 0, 0, M17_DROP_NONE) == -ENOENT);
    char cmd[400];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", dir);
    CHECK(!system(cmd));
}

int main(void) {
    test_requests();
    test_parse();
    test_reference();
    test_backstop();
    test_valid();
    test_log();
    if (failures) {
        fprintf(stderr, "M17 G5b/G5c tests: %d failed\n", failures);
        return 1;
    }
    printf("M17 G5b protection probe and G5c backstop PASS\n");
    return 0;
}
