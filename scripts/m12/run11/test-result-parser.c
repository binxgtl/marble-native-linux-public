#define main run11_main
#include "runner.c"
#undef main
#include <assert.h>
int main(void){
 const char *names[]={"firmware","interface","scan","association","wpa","dhcp","ping","disconnect","lease_reset","reconnect","reassociation","rewpa","redhcp","reping","network_cleanup"};
 char b[4096]={0};size_t at=0;
 for(unsigned i=0;i<15;i++)at+=(size_t)snprintf(b+at,sizeof(b)-at,"M12NET %s PASS rc=0\n",names[i]);
 assert(!network_results(b,0));assert(network_results(b,2));
 char copy[4096];strcpy(copy,b);strcat(copy,"M12NET ping PASS rc=0\n");assert(network_results(copy,0));
 for(unsigned drop=0;drop<15;drop++){
  at=0;copy[0]=0;for(unsigned i=0;i<15;i++)if(i!=drop)at+=(size_t)snprintf(copy+at,sizeof(copy)-at,"M12NET %s PASS rc=0\n",names[i]);
  assert(network_results(copy,0));
 }
 puts("Run11 production PID1 result parser: exact15 stages required; old/missing/duplicate/mismatched-exit success rejected; no hardware");return 0;
}
