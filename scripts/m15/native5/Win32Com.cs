// SPDX-License-Identifier: GPL-2.0-only
// Explicit device selection only. No enumeration, reconnect, purge or retry.
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
namespace M15Offline {
 [StructLayout(LayoutKind.Sequential)] public struct Overlap {
  public UIntPtr Internal, InternalHigh; public uint Offset, OffsetHigh; public IntPtr Event;
 }
 [StructLayout(LayoutKind.Sequential)] public struct CommStatus { public uint Flags, In, Out; }
 [StructLayout(LayoutKind.Sequential)] public struct Dcb {
  public uint Length, Baud, Flags; public ushort Reserved, XonLim, XoffLim;
  public byte ByteSize, Parity, StopBits, XonChar, XoffChar, ErrorChar, EofChar, EvtChar;
  public ushort Reserved1;
 }
 [StructLayout(LayoutKind.Sequential)] public struct CommTimeouts { public uint Interval, ReadMultiplier, ReadConstant, WriteMultiplier, WriteConstant; }
 public interface IWindowsIo {
  IntPtr Event(); bool Close(IntPtr h); int Error();
  bool Start(bool write,IntPtr h,IntPtr buffer,uint n,IntPtr overlap);
  uint Wait(IntPtr evt,uint ms); bool Result(IntPtr h,IntPtr overlap,out uint n);
  bool Cancel(IntPtr h,IntPtr overlap); bool Status(IntPtr h,out uint errors,out CommStatus status);
 }
 public sealed class WindowsIo:IWindowsIo {
  const string K="kernel32.dll";
  [DllImport(K,SetLastError=true)] static extern IntPtr CreateEventW(IntPtr attr,bool manual,bool initial,IntPtr name);
  [DllImport(K,SetLastError=true)] static extern bool CloseHandle(IntPtr h);
  [DllImport(K,SetLastError=true)] static extern bool ReadFile(IntPtr h,IntPtr b,uint n,IntPtr bytes,IntPtr ov);
  [DllImport(K,SetLastError=true)] static extern bool WriteFile(IntPtr h,IntPtr b,uint n,IntPtr bytes,IntPtr ov);
  [DllImport(K,SetLastError=true)] static extern uint WaitForSingleObject(IntPtr h,uint ms);
  [DllImport(K,SetLastError=true)] static extern bool GetOverlappedResult(IntPtr h,IntPtr ov,out uint n,bool wait);
  [DllImport(K,SetLastError=true)] static extern bool CancelIoEx(IntPtr h,IntPtr ov);
  [DllImport(K,SetLastError=true)] static extern bool ClearCommError(IntPtr h,out uint errors,out CommStatus stat);
  [DllImport(K,CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateFileW(string name,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
  [DllImport(K,SetLastError=true)] static extern bool GetCommState(IntPtr h,ref Dcb state);
  [DllImport(K,SetLastError=true)] static extern bool SetCommState(IntPtr h,ref Dcb state);
  [DllImport(K,SetLastError=true)] static extern bool SetCommTimeouts(IntPtr h,ref CommTimeouts timeouts);
  [DllImport(K,SetLastError=true)] static extern bool SetupComm(IntPtr h,uint input,uint output);
  public IntPtr Event(){return CreateEventW(IntPtr.Zero,true,false,IntPtr.Zero);}
  public bool Close(IntPtr h){return CloseHandle(h);} public int Error(){return Marshal.GetLastWin32Error();}
  public bool Start(bool w,IntPtr h,IntPtr b,uint n,IntPtr ov){return w?WriteFile(h,b,n,IntPtr.Zero,ov):ReadFile(h,b,n,IntPtr.Zero,ov);}
  public uint Wait(IntPtr h,uint ms){return WaitForSingleObject(h,ms);}
  public bool Result(IntPtr h,IntPtr ov,out uint n){return GetOverlappedResult(h,ov,out n,false);}
  public bool Cancel(IntPtr h,IntPtr ov){return CancelIoEx(h,ov);}
  public bool Status(IntPtr h,out uint e,out CommStatus s){return ClearCommError(h,out e,out s);}
  public static ComAdapter Open(string port,int timeoutMs) {return Open(port,timeoutMs,1000);}
  public static ComAdapter Open(string port,int timeoutMs,int idleTimeoutMs) {
   if(idleTimeoutMs<1||idleTimeoutMs>300000||timeoutMs<=idleTimeoutMs)throw new ArgumentException("bounded idle/operation deadlines required");
   if(!Regex.IsMatch(port,@"\ACOM[1-9][0-9]{0,3}\z"))throw new ArgumentException("explicit COM name required");
   // Overlapped, exclusive existing device. Never PURGE_RX or discard input.
   IntPtr h=CreateFileW(@"\\.\"+port,0xc0000000,0,IntPtr.Zero,3,0x40000000,IntPtr.Zero);
   if(h==new IntPtr(-1))throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
   try {
    Dcb d=new Dcb{Length=(uint)Marshal.SizeOf<Dcb>()};
    if(!GetCommState(h,ref d))throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
    // Binary 8N1, no software/hardware flow control, DTR enabled for ACM.
    d.Baud=115200;d.Flags=1u|(1u<<4)|(1u<<14);d.ByteSize=8;d.Parity=0;d.StopBits=0;
    // Return available data or wait for first byte up to the bounded idle budget. Zero is failure,
    // not EOF success. Outer deadlines and CancelIoEx remain authoritative.
    CommTimeouts t=new CommTimeouts{Interval=uint.MaxValue,ReadMultiplier=uint.MaxValue,ReadConstant=(uint)idleTimeoutMs};
    if(!SetCommState(h,ref d)||!SetupComm(h,1048576,65536)||!SetCommTimeouts(h,ref t))
     throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
    return new ComAdapter(new OverlappedDriver(new WindowsIo(),h),timeoutMs,2000);
   } catch {CloseHandle(h);throw;}
  }
 }
 public sealed class OverlappedDriver:IComDriver {
  readonly IWindowsIo api;IntPtr handle;Op live;
  sealed class Op {public GCHandle Pin;public IntPtr Ov,Event;public bool Terminal,Uncertain;public IoResult Result;}
  public OverlappedDriver(IWindowsIo api,IntPtr handle){if(api==null||handle==IntPtr.Zero||handle==new IntPtr(-1))throw new ArgumentException();this.api=api;this.handle=handle;}
  Op Checked(object token){if(live==null||!ReferenceEquals(live,token))throw new IOException("operation ownership");return live;}
  public object Begin(bool write,byte[] bytes,int offset,int count){
   if(live!=null||handle==IntPtr.Zero)throw new IOException("driver state");
   var op=new Op();
   try {
    op.Pin=GCHandle.Alloc(bytes,GCHandleType.Pinned);op.Event=api.Event();
    if(op.Event==IntPtr.Zero)throw new System.ComponentModel.Win32Exception(api.Error());
    op.Ov=Marshal.AllocHGlobal(Marshal.SizeOf<Overlap>());
    Marshal.StructureToPtr(new Overlap{Event=op.Event},op.Ov,false);
   } catch {if(op.Ov!=IntPtr.Zero)Marshal.FreeHGlobal(op.Ov);if(op.Event!=IntPtr.Zero)api.Close(op.Event);if(op.Pin.IsAllocated)op.Pin.Free();throw;}
   // Publish ownership before submission; never throw after submission. Even
   // an unexpected managed API exception returns the token as unresolved.
   live=op;
   try {
    if(!api.Start(write,handle,IntPtr.Add(op.Pin.AddrOfPinnedObject(),offset),(uint)count,op.Ov)) {
     int e=api.Error();if(e!=997){op.Terminal=true;op.Result=new IoResult(IoState.Failed,0,e);}
    }
   } catch {op.Uncertain=true;}
   return op;
  }
  public IoResult Wait(object token,int ms){
   var op=Checked(token);if(op.Uncertain)throw new IOException("submission exception: completion unknown");if(op.Terminal)return op.Result;
   uint n;bool done=api.Result(handle,op.Ov,out n);int error=done?0:api.Error();
   if(!done&&error==996){
    uint w=api.Wait(op.Event,(uint)ms);
    if(w==258)return new IoResult(IoState.Pending,0,996);
    if(w!=0)throw new System.ComponentModel.Win32Exception(api.Error());
    done=api.Result(handle,op.Ov,out n);error=done?0:api.Error();
   }
   if(!done&&error==996)return new IoResult(IoState.Pending,0,error);
   // Unexpected errors do not prove the kernel has stopped referencing Ov.
   if(!done&&error!=995)throw new System.ComponentModel.Win32Exception(error);
   op.Terminal=true;op.Result=new IoResult(done?IoState.Complete:IoState.Aborted,checked((int)n),error);return op.Result;
  }
  public int Cancel(object token){return api.Cancel(handle,Checked(token).Ov)?0:api.Error();}
  public void Release(object token){var op=Checked(token);if(!op.Terminal)throw new IOException("pending release");
   if(!api.Close(op.Event))throw new System.ComponentModel.Win32Exception(api.Error());
   Marshal.FreeHGlobal(op.Ov);op.Pin.Free();live=null;
  }
  public void Status(out int errors,out int queued){uint e;CommStatus s;if(!api.Status(handle,out e,out s))throw new System.ComponentModel.Win32Exception(api.Error());errors=checked((int)e);queued=checked((int)s.In);}
  public void Close(){if(live!=null)throw new IOException("pending close");if(handle!=IntPtr.Zero){if(!api.Close(handle))throw new System.ComponentModel.Win32Exception(api.Error());handle=IntPtr.Zero;}}
 }
}
