/* The integrated runtime's PID1 endpoint census rule (pure function; the /proc scan around it
 * needs a real PID1 and is not run here). */
#include "anchor_native.h"
#include <assert.h>
#include <stdio.h>

int main(void) {
    const unsigned long long ep=0xf000000ull, other=0x100003ull; /* synthetic device numbers */
    int fds[4]={0}; unsigned long long rdevs[4]={0};
    assert(!m11_census_pid1_endpoint(fds,rdevs,0,ep,-1,-1));
    fds[0]=3; rdevs[0]=other;
    assert(!m11_census_pid1_endpoint(fds,rdevs,1,ep,-1,-1));
    fds[1]=4; rdevs[1]=ep;
    assert(m11_census_pid1_endpoint(fds,rdevs,2,ep,-1,-1)==-1);          /* no anchor: none allowed */
    fds[1]=512; fds[2]=513; rdevs[2]=ep;
    assert(!m11_census_pid1_endpoint(fds,rdevs,3,ep,512,513));            /* exactly the pair */
    assert(m11_census_pid1_endpoint(fds,rdevs,2,ep,512,513)==-1);         /* guard missing */
    fds[3]=7; rdevs[3]=ep;
    assert(m11_census_pid1_endpoint(fds,rdevs,4,ep,512,513)==-1);         /* a third endpoint fd */
    fds[3]=512;
    assert(m11_census_pid1_endpoint(fds,rdevs,4,ep,512,513)==-1);         /* a repeated number */
    rdevs[3]=other;
    assert(!m11_census_pid1_endpoint(fds,rdevs,4,ep,512,513));            /* other devices ignored */
    puts("PASS integrated PID1 endpoint census rule: none without an anchor; exactly anchor and guard "
         "with it; a missing, extra or repeated endpoint fd is refused");
    return 0;
}
