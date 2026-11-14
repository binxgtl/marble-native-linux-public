#ifndef M12_RUN7_HWID_H
#define M12_RUN7_HWID_H
/* Pure bounded parser shared by PID1, parameter helper and offline tests.
 * Decimal bootloader uint values only; no shell expansion, device I/O or defaults. */
struct m12_hwid { unsigned v[4]; };
static const char *const m12_hwid_keys[]={"hwid_value","project","build_adc","project_adc"};
static inline unsigned long m12_hwid_len(const char *s) {
 unsigned long n=0;while(s[n])n++;return n;
}
static inline int m12_hwid_eq(const char *a,unsigned long n,const char *b) {
 unsigned long m=m12_hwid_len(b);if(n!=m)return 0;
 for(unsigned long i=0;i<n;i++)if(a[i]!=b[i])return 0;
 return 1;
}
static inline int m12_hwid_uint(const char *s,unsigned long n,unsigned *out) {
 if(n && s[n-1]=='\n')n--;
 if(!n || (n>1 && s[0]=='0'))return -1;
 unsigned v=0;
 for(unsigned long i=0;i<n;i++) {
  unsigned d=(unsigned char)s[i]-'0';
  if(d>9 || v>(4294967295u-d)/10)return -1;
  v=v*10+d;
 }
 *out=v;return 0;
}
static inline int m12_hwid_parse(const char *s,unsigned long n,int cmdline,struct m12_hwid *out) {
 if(!s || !out || !n || n>=16384)return -1;
 struct m12_hwid h={{0}};unsigned seen=0;
 for(unsigned long i=0;i<n;i++)if(!s[i] || ((unsigned char)s[i]<32 && s[i]!='\n' && s[i]!='\t'))return -1;
 for(unsigned long p=0;p<n;) {
  while(p<n && (s[p]==' ' || s[p]=='\t' || s[p]=='\n'))p++;
  unsigned long end=p;while(end<n && s[end]!=' ' && s[end]!='\t' && s[end]!='\n')end++;
  if(p==end)break;
  unsigned long key=p;
  if(cmdline) {
   if(end-p<5 || !m12_hwid_eq(s+p,5,"hwid.")){p=end;continue;}
   key+=5;
  }
  unsigned long eq=key;while(eq<end && s[eq]!='=')eq++;
  unsigned k;for(k=0;k<4;k++)if(m12_hwid_eq(s+key,eq-key,m12_hwid_keys[k]))break;
  if(k==4 || eq==end || seen&(1u<<k) || m12_hwid_uint(s+eq+1,end-eq-1,&h.v[k]))return -1;
  seen|=1u<<k;p=end;
 }
 if(seen!=15)return -1;
 *out=h;return 0;
}
static inline int m12_hwid_format(const struct m12_hwid *h,char *out,unsigned long cap) {
 unsigned long p=0;
 for(unsigned k=0;k<4;k++) {
  char digits[10];unsigned dn=0,v=h->v[k];
  do {digits[dn++]=(char)('0'+v%10);v/=10;}while(v);
  unsigned long kn=m12_hwid_len(m12_hwid_keys[k]);
  if(p+(k!=0)+kn+1+dn>=cap)return -1;
  if(k)out[p++]=' ';
  for(unsigned long i=0;i<kn;i++)out[p++]=m12_hwid_keys[k][i];
  out[p++]='=';while(dn)out[p++]=digits[--dn];
 }
 out[p]=0;return 0;
}
#endif
