#ifndef M12_RUN2_NETWORK_H
#define M12_RUN2_NETWORK_H

#include <stddef.h>

/* A deliberately secret-free representation. The WPA key is validated then
 * discarded; only the configured SSID remains in memory for scan matching. */
struct m12_wifi_credentials {
    unsigned char ssid[32];
    size_t ssid_len;
};

int m12_parse_wpa_config(const char *buf, size_t len,
                         struct m12_wifi_credentials *out);
int m12_scan_results_contains(const char *buf, size_t len,
                              const unsigned char *ssid, size_t ssid_len);
int m12_status_associated(const char *buf, size_t len);
int m12_status_wpa_completed(const char *buf, size_t len);

#endif
