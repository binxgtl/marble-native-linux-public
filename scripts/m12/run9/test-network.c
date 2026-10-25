#define _GNU_SOURCE
#define main m12_network_program_main
#include "network.c"
#undef main
#include "network.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static const char good[] =
    "ctrl_interface=DIR=/run/m12/wpa GROUP=0\n"
    "ap_scan=1\n"
    "network={\n"
    "ssid=666978747572652d6e6574\n"
    "psk=0000000000000000000000000000000000000000000000000000000000000000\n"
    "key_mgmt=WPA-PSK\n"
    "scan_ssid=0\n"
    "disabled=1\n"
    "}\n";

static void reject(const char *s) {
    struct m12_wifi_credentials c;
    memset(&c, 0xA5, sizeof(c));
    assert(m12_parse_wpa_config(s, strlen(s), &c) != 0);
    for (size_t i = 0; i < sizeof(c); ++i)
        assert(((const unsigned char *)&c)[i] == 0);
}

int main(void) {
    struct m12_wifi_credentials c;
    assert(m12_parse_wpa_config(good, sizeof(good) - 1, &c) == 0);
    assert(c.ssid_len == 11);
    assert(!memcmp(c.ssid, "fixture-net", 11));

    /* 1-byte SSID is legal; 32-byte SSID is the maximum. */
    char cfg[4097];
    const char *needle = "ssid=666978747572652d6e6574";
    const char *at = strstr(good, needle);
    assert(at);
    size_t prefix = (size_t)(at - good);
    size_t tail = strlen(at + strlen(needle));
    memcpy(cfg, good, prefix);
    memcpy(cfg + prefix, "ssid=41", 7);
    memcpy(cfg + prefix + 7, at + strlen(needle), tail + 1);
    assert(m12_parse_wpa_config(cfg, prefix + 7 + tail, &c) == 0);
    assert(c.ssid_len == 1 && c.ssid[0] == 'A');

    memcpy(cfg, good, prefix);
    memcpy(cfg + prefix, "ssid=", 5);
    for (size_t i = 0; i < 64; ++i) cfg[prefix + 5 + i] = '4';
    memcpy(cfg + prefix + 69, at + strlen(needle), tail + 1);
    assert(m12_parse_wpa_config(cfg, prefix + 69 + tail, &c) == 0);
    assert(c.ssid_len == 32);

    char bad[4097];
    snprintf(bad,sizeof(bad),"update_config=0\n%s",good);reject(bad);
    snprintf(bad,sizeof(bad),"update_config=1\n%s",good);reject(bad);
    strcpy(bad, good);
    char *p = strstr(bad, "disabled=1\n"); assert(p);
    memmove(p, p + strlen("disabled=1\n"), strlen(p + strlen("disabled=1\n")) + 1);
    reject(bad);
    strcpy(bad, good);
    p = strstr(bad, "psk=000"); assert(p); p[4] = 'z';
    reject(bad);
    strcpy(bad, good);
    p = strstr(bad, "ssid=666"); assert(p); p[5] = 'g';
    reject(bad);
    strcpy(bad, good);
    p = strstr(bad, "network={\n"); assert(p);
    strcat(bad, "network={\n}\n");
    reject(bad);
    reject("ssid=fixture-net\n");
    assert(m12_parse_wpa_config(good, sizeof(good), &c) != 0); /* includes NUL */
    assert(m12_parse_wpa_config(good, 4097, &c) != 0);

    static const unsigned char target[] = "fixture-net";
    static const char scan[] =
        "bssid / frequency / signal level / flags / ssid\n"
        "02:00:00:00:00:01\t2412\t-42\t[WPA2-PSK-CCMP][ESS]\tother-net\n"
        "02:00:00:00:00:02\t2437\t-50\t[WPA2-PSK-CCMP][ESS]\tfixture-net\n";
    assert(m12_scan_results_contains(scan, sizeof(scan) - 1, target, sizeof(target) - 1));
    assert(!m12_scan_results_contains(scan, sizeof(scan) - 1, target, sizeof(target) - 2));
    assert(!m12_scan_results_contains("header\n", 7, target, sizeof(target) - 1));
    assert(!m12_scan_results_contains(scan, sizeof(scan) - 1, NULL, sizeof(target) - 1));

    static const char associated[] = "wpa_state=ASSOCIATED\nid=0\n";
    static const char handshaking[] = "wpa_state=4WAY_HANDSHAKE\nid=0\n";
    static const char complete[] = "wpa_state=COMPLETED\nid=0\n";
    static const char bogus[] = "xwpa_state=COMPLETED\n";
    assert(m12_status_associated(associated, sizeof(associated) - 1));
    assert(m12_status_associated(handshaking, sizeof(handshaking) - 1));
    assert(m12_status_associated(complete, sizeof(complete) - 1));
    assert(!m12_status_wpa_completed(associated, sizeof(associated) - 1));
    assert(m12_status_wpa_completed(complete, sizeof(complete) - 1));
    assert(!m12_status_wpa_completed(bogus, sizeof(bogus) - 1));
    assert(!m12_status_wpa_completed("wpa_state=COMPLETED\nid=1\n",sizeof("wpa_state=COMPLETED\nid=1\n")-1));
    assert(!m12_status_wpa_completed("wpa_state=COMPLETED\nid=0\nid=0\n",sizeof("wpa_state=COMPLETED\nid=0\nid=0\n")-1));
    assert(!m12_status_wpa_completed("wpa_state=COMPLETED\nwpa_state=DISCONNECTED\nid=0\n",sizeof("wpa_state=COMPLETED\nwpa_state=DISCONNECTED\nid=0\n")-1));
    char leasebuf[256], ip[16], mask[16], gw[16];unsigned prefixbits;
    strcpy(leasebuf,"192.0.2.2\n255.255.255.0\n192.0.2.1\n");
    assert(!parse_lease(leasebuf,ip,sizeof(ip),mask,sizeof(mask),gw,sizeof(gw),&prefixbits));
    assert(prefixbits==24&&!strcmp(gw,"192.0.2.1"));
    strcpy(leasebuf,"192.0.2.2\n255.255.255.0\n192.0.2.1\nGARBAGE");
    assert(parse_lease(leasebuf,ip,sizeof(ip),mask,sizeof(mask),gw,sizeof(gw),&prefixbits));
    strcpy(leasebuf,"192.0.2.2\n255.0.255.0\n192.0.2.1\n");
    assert(parse_lease(leasebuf,ip,sizeof(ip),mask,sizeof(mask),gw,sizeof(gw),&prefixbits));
    strcpy(leasebuf,"192.0.2.2\n255.255.255.0\n192.0.2.1");
    assert(parse_lease(leasebuf,ip,sizeof(ip),mask,sizeof(mask),gw,sizeof(gw),&prefixbits));
    puts("M12 network parser/privacy fixtures PASS (synthetic only)");
    return 0;
}
