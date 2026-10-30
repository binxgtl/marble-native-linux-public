/* SPDX-License-Identifier: GPL-2.0-only */
#include "m9-kms.h"
#include <stdint.h>
#include <stdlib.h>
/* The M7 D4 contract through m9-kms: commit one colour, hold, atomic disable, verify, free.
 * Exit 0 only after a verified disable, so PID1 knows no panel stays lit across the cycle. */
int main(int argc,char **argv){
 if(argc!=3)return 64;
 char *end;
 unsigned long color=strtoul(argv[1],&end,16);
 if(*end||color>0xffffffffu)return 64;
 unsigned long hold=strtoul(argv[2],&end,10);
 if(*end||hold>3600000u)return 64;
 return m9_kms_cpu_checkpoint("/dev/dri/card0",(uint32_t)color,(unsigned)hold);
}
