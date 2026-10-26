// SPDX-License-Identifier: GPL-2.0-only
// Offline injectable transport only. No COM opener or device enumeration.
using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Diagnostics;
namespace M15Offline {
 public interface ITransport {
  int Read(byte[] buffer); // bounded completion required; zero means disconnect
  void Reconcile(); // must resolve all outstanding reads and transport errors
  int Write(byte[] buffer,int offset,int count);
 }
 public sealed class Scanner {
  int phase=0,file=0,index=0; long sequence=0,payload=0,offset=0,total=0;
  readonly long[] sizes=new long[6]; readonly StringBuilder line=new StringBuilder();
  public bool Done {get;private set;}
  public long Bytes {get{return total;}}
  static long Num(string s) {
   if(!Regex.IsMatch(s,@"\A(?:0|[1-9][0-9]{0,9})\z"))throw new InvalidDataException("integer");
   return long.Parse(s,System.Globalization.CultureInfo.InvariantCulture);
  }
  static bool Hash(string s){return Regex.IsMatch(s,@"\A[0-9a-f]{64}\z");}
  void Header(string s) {
   string[] a=s.Split(' ');
   if(phase==0){
    if(a.Length!=4||a[0]!="M15E1"||!Regex.IsMatch(a[1],@"\A[0-9a-f]{32}\z")||a[1]==new string('0',32)||!Hash(a[2])||a[3]!="6")throw new InvalidDataException("header");
    phase=1;return;
   }
   if(phase==1){
    if(a.Length!=4||a[0]!="I"||Num(a[1])!=index||!Hash(a[3]))throw new InvalidDataException("manifest");
    long n=Num(a[2]);long[] limits={2000000,262144,1048576,8192,256,8388608};
    if(n>limits[index])throw new InvalidDataException("budget");
    sizes[index++]=n;if(index==6)phase=2;return;
   }
   if(phase==2){if(s!="END")throw new InvalidDataException("end");phase=3;return;}
   while(file<6 && offset==sizes[file]){file++;offset=0;}
   if(file==6){
    if(a.Length!=5||a[0]!="F"||Num(a[1])!=sequence||Num(a[2])!=total-s.Length-1||!Hash(a[3])||!Hash(a[4]))throw new InvalidDataException("final");
    Done=true;return;
   }
   if(a.Length!=5||a[0]!="D"||Num(a[1])!=sequence||Num(a[2])!=file||Num(a[3])!=offset||Num(a[4])!=Math.Min(1024,sizes[file]-offset))throw new InvalidDataException("frame");
   payload=Num(a[4]);sequence++;
  }
  public void Feed(byte[] b,int n) {
   if(n<1||n>b.Length)throw new InvalidDataException("read-count");
   for(int i=0;i<n;i++){
    if(Done||++total>16777216)throw new InvalidDataException("trailing-or-budget");
    if(payload>0){payload--;offset++;continue;}
    byte c=b[i];
    if(c==10){string s=line.ToString();line.Clear();Header(s);}
    else {if(c<32||c>126||line.Length>=1023)throw new InvalidDataException("line");line.Append((char)c);}
   }
  }
 }
 public static class Receiver {
  // Verifier must independently replay SAVED bytes and persist its receipt before
  // returning ACK. It is a trusted adapter dependency, not a source of framing.
  public static long Capture(ITransport transport,string path,Func<string,byte[]> verify,int deadlineMs) {
   if(deadlineMs<1||deadlineMs>300000)throw new ArgumentException("deadline");
   var clock=Stopwatch.StartNew();var scan=new Scanner();byte[] b=new byte[65536];
   using(var f=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None)){
    while(!scan.Done){
     if(clock.ElapsedMilliseconds>=deadlineMs)throw new TimeoutException();
     int n=transport.Read(b);
     if(n<=0||n>b.Length)throw new IOException("disconnect-or-count");
     // Preserve even a corrupt received chunk before failing qualification.
     f.Write(b,0,n);scan.Feed(b,n);
    }
    transport.Reconcile();
    if(clock.ElapsedMilliseconds>=deadlineMs)throw new TimeoutException();
    f.Flush(true);
   }
   byte[] ack=verify(path);
   if(ack==null||ack.Length>256||!Regex.IsMatch(Encoding.ASCII.GetString(ack),@"\AM15ACK1 [0-9a-f]{32} [0-9a-f]{64} [0-9a-f]{64}\n\z"))throw new InvalidDataException("ack");
   transport.Reconcile();
   int off=0;
   while(off<ack.Length){
    if(clock.ElapsedMilliseconds>=deadlineMs)throw new TimeoutException();
    int n=transport.Write(ack,off,ack.Length-off);
    if(n<=0||n>ack.Length-off)throw new IOException("ack-write");off+=n;
   }
   return scan.Bytes; // ACK accepted by transport, not sender receipt or device safety
  }
 }
 public sealed class FakeTransport:ITransport {
  readonly byte[] bytes;readonly int chunk;readonly string fault;int at=0;
  public readonly MemoryStream Ack=new MemoryStream();public int Reads=0;
  public FakeTransport(byte[] bytes,int chunk,string fault){this.bytes=bytes;this.chunk=chunk;this.fault=fault;}
  public int Read(byte[] b){Reads++;if(fault=="read")throw new IOException("fixture");
   if(at==bytes.Length)throw new Exception("EOF read forbidden: sender waits for ACK");
   int n=Math.Min(Math.Min(chunk,b.Length),bytes.Length-at);Array.Copy(bytes,at,b,0,n);at+=n;return n;}
  public void Reconcile(){if(fault=="pending"||fault=="overrun"||at!=bytes.Length)throw new IOException("unresolved-or-extra");}
  public int Write(byte[] b,int off,int n){if(fault=="ack")return 0;n=Math.Min(n,3);Ack.Write(b,off,n);return n;}
 }
}
