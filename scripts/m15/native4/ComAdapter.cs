// SPDX-License-Identifier: GPL-2.0-only
// COM operation lifecycle over an injected driver. No native handle is opened.
using System;
using System.IO;
namespace M15Offline {
 public enum IoState { Pending, Complete, Aborted, Failed }
 public struct IoResult {
  public IoState State;public int Bytes;public int Error;
  public IoResult(IoState state,int bytes,int error){State=state;Bytes=bytes;Error=error;}
 }
 public interface IComDriver {
  // Driver owns pinned buffer/OVERLAPPED until a terminal result and Release.
  object Begin(bool write,byte[] buffer,int offset,int count);
  IoResult Wait(object operation,int milliseconds);
  int Cancel(object operation); // request only; even ERROR_NOT_FOUND is not completion
  void Release(object operation);
  void Status(out int errors,out int queuedInput);
  void Close();
 }
 public sealed class ComAdapter:ITransport,IDisposable {
  readonly IComDriver driver;readonly int timeout,cancelBudget;
  object active;bool failed,closed;
  public int LastError {get;private set;}
  public int CancelError {get;private set;}
  public bool OwnershipUnresolved {get{return active!=null;}}
  public bool Failed {get{return failed;}}
  public ComAdapter(IComDriver driver,int timeout,int cancelBudget){
   if(driver==null||timeout<1||timeout>300000||cancelBudget<1||cancelBudget>5000)throw new ArgumentException();
   this.driver=driver;this.timeout=timeout;this.cancelBudget=cancelBudget;
  }
  void Usable(){if(failed||closed||active!=null)throw new IOException("COM terminal or unresolved");}
  void CheckStatus(bool empty){
   int errors,queued;driver.Status(out errors,out queued);
   if(errors!=0||queued<0||(empty&&queued!=0)){LastError=errors;throw new IOException("COM errors or extra bytes");}
  }
  int Transfer(bool write,byte[] b,int offset,int count){
   Usable();
   if(b==null||offset<0||count<1||offset>b.Length-count)throw new ArgumentException();
   try {
    CheckStatus(write);
    active=driver.Begin(write,b,offset,count);
    if(active==null)throw new IOException("COM missing operation");
    IoResult r=driver.Wait(active,timeout);
    bool expired=r.State==IoState.Pending;
    if(expired){
     CancelError=driver.Cancel(active);
     r=driver.Wait(active,cancelBudget);
    }
    if(r.State==IoState.Pending)throw new IOException("COM cancellation unresolved: retain operation and handle");
    if(r.State!=IoState.Complete&&r.State!=IoState.Aborted&&r.State!=IoState.Failed)throw new IOException("COM invalid completion");
    // Release only terminal operations. A throwing Release retains ownership.
    driver.Release(active);active=null;LastError=r.Error;
    if(expired)throw new TimeoutException("COM deadline exceeded even if cancellation raced completion");
    if(r.State!=IoState.Complete||r.Error!=0||r.Bytes<=0||r.Bytes>count)throw new IOException("COM completion error/count");
    CheckStatus(false);return r.Bytes;
   }catch{failed=true;throw;}
  }
  public int Read(byte[] b){return Transfer(false,b,0,b.Length);}
  public int Write(byte[] b,int offset,int count){return Transfer(true,b,offset,count);}
  public void Reconcile(){Usable();try{CheckStatus(true);}catch{failed=true;throw;}}
  public void Dispose(){
   if(closed)return;
   if(active!=null){failed=true;throw new IOException("COM retained: unresolved operation cannot be closed");}
   try{driver.Close();closed=true;}catch{failed=true;throw;}
  }
 }
 // Scripted fake driver validates operation lifetime and unexpected calls.
 public sealed class ComFake:IComDriver {
  public IoResult[] Results={new IoResult(IoState.Complete,1,0)};
  public int Errors,Queued,CancelResult,Waits,Cancels,Releases,Closes,Begins;
  public bool ThrowWait,ThrowBegin,ThrowRelease,ThrowStatus,ThrowCancel;
  object live;
  public object Begin(bool write,byte[] b,int offset,int count){
   Begins++;if(ThrowBegin)throw new IOException("begin");if(live!=null)throw new Exception("double begin");
   live=new object();return live;
  }
  public IoResult Wait(object op,int ms){
   if(op!=live)throw new Exception("wrong operation");Waits++;
   if(ThrowWait)throw new IOException("wait");return Results[Math.Min(Waits-1,Results.Length-1)];
  }
  public int Cancel(object op){if(op!=live)throw new Exception();Cancels++;if(ThrowCancel)throw new IOException("cancel");return CancelResult;}
  public void Release(object op){if(op!=live)throw new Exception();if(ThrowRelease)throw new IOException("release");Releases++;live=null;}
  public void Status(out int errors,out int queued){if(ThrowStatus)throw new IOException("status");errors=Errors;queued=Queued;}
  public void Close(){if(live!=null)throw new Exception("closed pending");Closes++;}
 }
 public static class ComTests {
  static void Must(bool v){if(!v)throw new Exception("COM test assertion");}
  static void Reject(Action action){bool bad=false;try{action();}catch{bad=true;}Must(bad);}
  public static int Run(){
   int tests=0;byte[] bytes=new byte[16];
   var ok=new ComFake();var a=new ComAdapter(ok,10,5);Must(a.Read(bytes)==1);a.Reconcile();Must(a.Write(bytes,0,16)==1);a.Dispose();Must(ok.Releases==2&&ok.Closes==1);tests++;
   foreach(var state in new[]{IoState.Aborted,IoState.Failed}){
    var d=new ComFake{Results=new[]{new IoResult(state,0,995)}};a=new ComAdapter(d,10,5);
    Reject(()=>a.Read(bytes));Must(a.Failed&&!a.OwnershipUnresolved&&a.LastError==995);a.Dispose();tests++;
   }
   foreach(int n in new[]{0,-1,17}){
    var d=new ComFake{Results=new[]{new IoResult(IoState.Complete,n,0)}};a=new ComAdapter(d,10,5);Reject(()=>a.Read(bytes));Must(a.Failed);a.Dispose();tests++;
   }
   foreach(int cancel in new[]{0,1168,5})foreach(var finish in new[]{IoState.Pending,IoState.Complete,IoState.Aborted}){
    var d=new ComFake{CancelResult=cancel,Results=new[]{new IoResult(IoState.Pending,0,997),new IoResult(finish,1,0)}};
    a=new ComAdapter(d,10,5);Reject(()=>a.Read(bytes));Must(a.Failed&&d.Cancels==1&&a.CancelError==cancel);
    if(finish==IoState.Pending){Must(a.OwnershipUnresolved&&d.Releases==0);Reject(()=>a.Dispose());Must(d.Closes==0);}
    else{Must(!a.OwnershipUnresolved);a.Dispose();Must(d.Closes==1);}
    Reject(()=>a.Write(bytes,0,1));Must(d.Begins==1);tests++;
   }
   foreach(int error in new[]{1,2,4,8,16}){
    var d=new ComFake{Errors=error};a=new ComAdapter(d,10,5);Reject(()=>a.Read(bytes));Must(d.Begins==0);a.Dispose();tests++;
   }
   var extra=new ComFake{Queued=1};a=new ComAdapter(extra,10,5);Reject(()=>a.Reconcile());Reject(()=>a.Write(bytes,0,1));Must(extra.Begins==0);a.Dispose();tests++;
   foreach(string fault in new[]{"begin","wait","release","status","cancel"}){
    var d=new ComFake{ThrowBegin=fault=="begin",ThrowWait=fault=="wait",ThrowRelease=fault=="release",ThrowStatus=fault=="status",ThrowCancel=fault=="cancel"};
    if(fault=="cancel")d.Results=new[]{new IoResult(IoState.Pending,0,997)};
    a=new ComAdapter(d,10,5);Reject(()=>a.Read(bytes));Must(a.Failed);
    if(fault=="wait"||fault=="release"||fault=="cancel"){Must(a.OwnershipUnresolved);Reject(()=>a.Dispose());Must(d.Closes==0);}
    else a.Dispose();tests++;
   }
   return tests;
  }
 }
}
