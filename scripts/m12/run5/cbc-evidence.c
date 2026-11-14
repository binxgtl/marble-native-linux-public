/* SPDX-License-Identifier: GPL-2.0-only */
#include "cbc-evidence.h"
#include <errno.h>
#include <string.h>
#include <stdio.h>
int m12_golden_admitted(const struct m12_caldb *s,const struct m12_bootstrap_facts *f,const struct m12_golden_scope *g) {
 if(m12_cbc_admitted(s,f))return 1;
 /* This is permission for a scoped experiment, NOT a native BDF response.
  * Keep f->bdf_cal_requirement UNKNOWN until the actual kernel record. */
 if(f->bdf_cal_requirement!=M12_CAL_UNKNOWN || !g || g->device!=1 ||
    g->firmware!=1 || g->bdf!=1 || g->closure!=1 || g->trace!=1 || g->operator_authorized!=1)return 0;
 struct m12_bootstrap_facts prior=*f;prior.bdf_cal_requirement=M12_CAL_NOT_REQUIRED;
 return m12_cbc_admitted(s,&prior);
}
int m12_cbc_line(struct m12_cbc_evidence *s,const char *line) {
 const char *m=strstr(line,"cnss: ");if(!m)return 0;m+=6;
 if(!strncmp(m,"FW name is ",11)) {
  if(strcmp(m,"FW name is qca6490/amss20.bin, FW fallback name is amss20.bin"))s->fault=-EXDEV;
  else s->firmware=1;
  return 9;
 }
 if(strstr(m,"COLD_BOOT_CAL_START(")){s->start=1;return 1;}
 if(strstr(m,"COLD_BOOT_CAL_DONE(")){s->done=1;return 2;}
 if(!strcmp(m,"Calibration completed successfully")){s->completed=1;return 3;}
 if(strstr(m,"mode: MISSION(0)")){s->mission=1;return 4;}
 if(!strncmp(m,"Downloading BDF:",16)) {
  if(strcmp(m,"Downloading BDF: qca6490/bd_m16tgf.elf, size: 59872"))s->fault=-EXDEV;
  else s->bdf=1;
  return 5;
 }
 if(!strncmp(m,"Host BDF config:",16)) {
  unsigned xpa,cal;int used=0;
  if(sscanf(m,"Host BDF config: HW_XPA: %u CalDB: %u%n",&xpa,&cal,&used)!=2 || m[used] || xpa!=1 || cal>1)s->fault=-EPROTO;
  else {
   enum m12_cal_requirement r=cal?M12_CAL_REQUIRED:M12_CAL_NOT_REQUIRED;
   if(s->requirement && s->requirement!=r)s->fault=-EPROTO;
   else s->requirement=r;
  }
  return 6;
 }
 if(!strncmp(m,"Target capability:",18)) {
  if(strcmp(m,"Target capability: chip_id: 0x12, chip_family: 0xb, board_id: 0xff, soc_id: 0x400c1211, otp_version: 0x440102"))s->fault=-EXDEV;
  else s->capability=1;
  return 7;
 }
 if(strstr(m,"CAL DB file"))return 8;
 return 0;
}
int m12_cbc_ready(const struct m12_cbc_evidence *s,int idle,int seed) {
 return !s->fault && s->start && s->done && s->completed && s->mission &&
  s->bdf && s->capability && s->firmware && idle==1 &&
  (s->requirement==M12_CAL_NOT_REQUIRED || (s->requirement==M12_CAL_REQUIRED && seed==1));
}
