#define main unused_network_main
#include "network.c"
#undef main
int main(int argc,char **argv){
 if(argc!=2)return 2;
 char b[4097];size_t n;struct m12_wifi_credentials c;
 if(readfile(argv[1],b,sizeof(b),&n))return 2;
 int rc=m12_parse_wpa_config(b,n,&c);secret_clear(b,sizeof(b));secret_clear(&c,sizeof(c));return rc?1:0;
}
