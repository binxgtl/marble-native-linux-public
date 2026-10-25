/* Exact canonical ELF .modinfo and __this_module names, not filename guesses. */
#ifndef M12_MODULE_NAMES_H
#define M12_MODULE_NAMES_H
#include <string.h>
static const struct { const char *filename, *registered; } wlan_names[] = {
 {"cfg80211.ko", "cfg80211"},
 {"cnss_nl.ko", "cnss_nl"},
 {"cnss_prealloc.ko", "cnss_prealloc"},
 {"cnss_utils.ko", "cnss_utils"},
 {"mi_cnss_statistic.ko", "mi_cnss_statistic"},
 {"qca_cld3_qca6490.ko", "qca6490"},
};
static inline const char *wlan_registered_name(const char *filename) {
 for(unsigned i=0;i<sizeof(wlan_names)/sizeof(*wlan_names);i++)
  if(!strcmp(filename,wlan_names[i].filename)) return wlan_names[i].registered;
 return NULL;
}
#endif
