using System;using System.IO;using System.Threading;
public sealed class FixtureSource : M11Integrity.Source {
 public byte[] Data;public int At,Width=8191,FaultAt=-1;public string Fault="";public bool TimeoutOnce;
 public override int Read(byte[] b,int o,int n){
  if(TimeoutOnce){TimeoutOnce=false;throw new TimeoutException();}
  if(FaultAt>=0 && At>=FaultAt){
   if(Fault=="timeout"){Thread.Sleep(5);throw new TimeoutException();}
   if(Fault=="bad-count")return n+1;
   if(Fault=="disconnect")throw new IOException("disconnected");
  }
  if(At==Data.Length)return 0;
  int k=Math.Min(Math.Min(n,Data.Length-At),Width);Buffer.BlockCopy(Data,At,b,o,k);At+=k;return k;
 }
 public override string[] Errors(){return FaultAt>=0 && At>=FaultAt && (Fault=="RXOver" || Fault=="Frame")?new[]{Fault}:new string[0];}
}
public sealed class TestSink : MemoryStream {
 public string Fault="";
 public override void Write(byte[] b,int o,int n){
  if(Fault=="short-write"){base.Write(b,o,Math.Min(n,6));throw new IOException("partial sink");}
  if(Fault=="backpressure")Thread.Sleep(1);
  base.Write(b,o,n);
 }
 public override void Flush(){if(Fault=="flush")throw new IOException("flush failed");base.Flush();}
}
