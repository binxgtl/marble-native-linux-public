// Binary hot path: no PnP, sleeps, text sinks, UTF8 or PowerShell callbacks.
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Ports;
using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
namespace M11Integrity {
 public abstract class Source { public abstract int Read(byte[] b,int o,int n); public abstract string[] Errors(); }
 public sealed class SerialSource : Source {
  readonly SerialPort port; readonly List<string> errors=new List<string>();
  public SerialSource(SerialPort p){port=p;port.ErrorReceived+=OnError;}
  void OnError(object sender,SerialErrorReceivedEventArgs e){lock(errors)errors.Add(e.EventType.ToString());}
  public override int Read(byte[] b,int o,int n){return port.Read(b,o,n);}
  public override string[] Errors(){lock(errors)return errors.ToArray();}
  public void Detach(){port.ErrorReceived-=OnError;}
 }
 public sealed class Receipt { public long Bytes;public long Reads;public long ReadTimeouts;public string Reason="deadline",Detail="";public bool FlushClean; }
 // Structural boundary detector only; independent strict SHA validator qualifies.
 public sealed class Boundary {
  readonly byte[] header=new byte[64];int at;long left;bool final;bool ended;
  public void Feed(byte[] b,int n) {
   for(int i=0;i<n;i++){
    if(ended)throw new InvalidDataException("trailing-bytes");
    if(left>0){if(--left==0 && final)ended=true;continue;}
    if(at==header.Length)throw new InvalidDataException("header-too-long");
    header[at++]=b[i];if(b[i]!=10)continue;
    string h=Encoding.ASCII.GetString(header,0,at);
    Match m=Regex.Match(h,@"\AM11I3 ([SKEWF]) (0|[1-9][0-9]{0,8}) ([1-9][0-9]{0,4})\n\z");
    if(!m.Success)throw new InvalidDataException("invalid-header");
    left=long.Parse(m.Groups[3].Value,System.Globalization.CultureInfo.InvariantCulture);
    if(left>16384)throw new InvalidDataException("invalid-length");
    final=m.Groups[1].Value=="F";at=0;
   }
  }
  public bool Ended {get{return ended;}}
 }
 public static class Reader {
  public static Receipt Receive(Source source,Stream raw,int milliseconds,long maxBytes) {
   if(maxBytes<1 || maxBytes>67108864)throw new ArgumentOutOfRangeException("maxBytes");
   Receipt r=new Receipt();Boundary boundary=new Boundary();byte[] b=new byte[65536];Stopwatch clock=Stopwatch.StartNew();
   while(clock.ElapsedMilliseconds<milliseconds){
    if(source.Errors().Length!=0){r.Reason="serial-error";break;}
    int n;
    try{n=source.Read(b,0,b.Length);r.Reads++;}
    catch(TimeoutException){r.ReadTimeouts++;continue;}
    catch(Exception e){r.Reason="read-error";r.Detail=e.GetType().FullName+": "+e.Message;break;}
    if(n==0){r.Reason="unexpected-eof";break;}
    if(n<0 || n>b.Length){r.Reason="invalid-read-count";break;}
    if(n>maxBytes-r.Bytes){r.Reason="byte-budget";break;}
    // Stream.Write either accepts all n or throws. Any partial sink is a failure.
    try{raw.Write(b,0,n);r.Bytes+=n;}
    catch(Exception e){r.Reason="raw-write-error";r.Detail=e.Message;break;}
    try{boundary.Feed(b,n);}
    catch(Exception e){r.Reason="framing-error";r.Detail=e.Message;break;}
    if(source.Errors().Length!=0){r.Reason="serial-error";break;}
    if(boundary.Ended){r.Reason="terminal-frame";break;}
   }
   try{raw.Flush();r.FlushClean=true;}
   catch(Exception e){r.Reason="flush-error";r.Detail=e.Message;}
   return r;
  }
 }
}
