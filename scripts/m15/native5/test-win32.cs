// SPDX-License-Identifier: GPL-2.0-only
using System;
using System.IO;
using System.Runtime.InteropServices;
namespace M15Offline {
 public sealed class WindowsFake:IWindowsIo {
  public string Fault="";public int Calls,Closes,CancelCalls,Err;public IntPtr Ov,Buffer;public bool cancelled;
  public IntPtr Event(){return new IntPtr(42);}
  public bool Close(IntPtr h){Closes++;return true;}
  public int Error(){return Err;}
  public bool Start(bool w,IntPtr h,IntPtr b,uint n,IntPtr ov){
   Ov=ov;Buffer=b;if(Fault=="submit")throw new IOException();
   if(Fault=="start-error"){Err=5;return false;}
   Err=997;return false;
  }
  public uint Wait(IntPtr e,uint ms){if(Fault=="wait"){Err=6;return uint.MaxValue;}return 258;}
  public bool Result(IntPtr h,IntPtr ov,out uint n){
   Calls++;n=0;if(Ov!=ov)throw new Exception();
   if(Fault=="pending"||Fault=="cancel-error"||Fault=="wait"){Err=996;return false;}
   if(Fault=="unknown-error"){Err=6;return false;}
   if(Fault=="cancelled"){
    Err=cancelled?995:996;return false;
   }
   if(Fault=="race"&&!cancelled){Err=996;return false;}
   Marshal.WriteByte(Buffer,0,99);n=1;return true;
  }
  public bool Cancel(IntPtr h,IntPtr ov){CancelCalls++;cancelled=true;Err=Fault=="cancel-error"?5:1168;return Fault!="cancel-error";}
  public bool Status(IntPtr h,out uint e,out CommStatus s){e=Fault=="overrun"?2u:0;s=new CommStatus();return true;}
 }
 public static class NativeIoTests {
  static void Check(bool b){if(!b)throw new Exception("native adapter assertion");}
  public static int Run(){
   Check(Marshal.SizeOf<Overlap>()==(IntPtr.Size==8?32:20));
   Check(Marshal.SizeOf<Dcb>()==28&&Marshal.SizeOf<CommStatus>()==12&&Marshal.SizeOf<CommTimeouts>()==20);
   int tests=1;
   foreach(string fault in new[]{"","start-error","submit","pending","cancel-error","cancelled","race","wait","unknown-error","overrun"}){
    var f=new WindowsFake{Fault=fault};var a=new ComAdapter(new OverlappedDriver(f,new IntPtr(43)),10,5);byte[] b=new byte[4];bool fail=false;
    try{Check(a.Read(b)==1&&b[0]==99);}catch{fail=true;}
    Check(fail==(fault!=""));
    bool retain=fault=="submit"||fault=="pending"||fault=="cancel-error"||fault=="wait"||fault=="unknown-error";
    Check(a.OwnershipUnresolved==retain);
    if(retain){Check(a.Retained&&f.Closes==0);try{a.Dispose();throw new Exception("closed live op");}catch(IOException){}Check(f.Closes==0);}
    else{a.Dispose();Check(f.Closes==(fault=="overrun"?1:2));}
    tests++;
   }
   foreach(string port in new[]{"","COM0","COM1/other","\\\\.\\COM1","com1"}){
    try{WindowsIo.Open(port,10);throw new Exception("bad port accepted");}catch(ArgumentException){}tests++;
   }
   return tests;
  }
 }
}
