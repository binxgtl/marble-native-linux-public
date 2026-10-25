/* Offline successor policy: retain provider instances until normal reboot.
 * This avoids vendor exit paths; it does not certify kernel resource balance. */
#ifndef M12_CLEANUP_RETENTION_POLICY_H
#define M12_CLEANUP_RETENTION_POLICY_H
#include <string.h>
static const char *m12_retention_reason(const char *module) {
 if(!strcmp(module,"msm_qmp.ko"))return "shared AOP provider retained to reboot";
 if(!strcmp(module,"pci-msm-drv.ko"))return "vendor remove lacks clock/rail state guard; retained to reboot";
 if(!strcmp(module,"hwid.ko"))return "vendor exit removes deleted sysfs parent; retained to reboot";
 if(!strcmp(module,"wlan_firmware_service.ko"))return "no module exit; descriptor provider retained to reboot";
 return NULL;
}
static unsigned m12_retained_count(const char *const *modules,unsigned loaded) {
 unsigned n=0;
 for(unsigned i=0;i<loaded;i++)if(m12_retention_reason(modules[i]))n++;
 return n;
}
#endif
