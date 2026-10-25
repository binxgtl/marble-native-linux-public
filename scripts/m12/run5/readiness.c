/* Read-only, no credentials/RF/calibration. Same production readiness checks. */
#define main m12_network_unused_main
#include "../run3/network.c"
#undef main
int m12_readiness_main(void) {
 char bdf[64]={0},ifn[IFNAMSIZ]={0}; unsigned index=0;
 crumb("readiness_begin",0);
 /* PID1 has already required actual CBC/MISSION evidence. */
 int rc=wait_stack_ready(bdf,sizeof(bdf),ifn,sizeof(ifn),&index);
 int raw=rc?-(errno?errno:EIO):0;
 int present=access("/sys/kernel/cnss/fs_ready",F_OK)==0;
 crumb("readiness_return",raw);
 printf("M12READY ready=%d raw_rc=%d qca6490_loaded=%d fs_ready_present=%d fs_ready_triggered=1\n",
        rc==0,raw,loaded("qca6490"),present);
 if(fflush(stdout)) return 3;
 return rc?2:0;
}
#ifndef M12_RUN5_EMBEDDED
int main(void){return m12_readiness_main();}
#endif
