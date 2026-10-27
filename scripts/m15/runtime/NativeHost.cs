// SPDX-License-Identifier: GPL-2.0-only
using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
namespace M15Offline {
 public static class NativeHost {
  static string Line(ITransport t,int ms){
   var time=Stopwatch.StartNew();var line=new StringBuilder();byte[] b=new byte[1];
   while(true){if(time.ElapsedMilliseconds>=ms)throw new TimeoutException();if(t.Read(b)!=1)throw new IOException("handshake disconnect");if(time.ElapsedMilliseconds>=ms)throw new TimeoutException();if(b[0]==10)return line.ToString();if(b[0]<32||b[0]>126||line.Length>=255)throw new InvalidDataException("handshake line");line.Append((char)b[0]);}
  }
  static void Send(ITransport t,string s){var time=Stopwatch.StartNew();byte[] b=Encoding.ASCII.GetBytes(s);int at=0;while(at<b.Length){if(time.ElapsedMilliseconds>=120000)throw new TimeoutException();int n=t.Write(b,at,b.Length-at);if(n<=0||n>b.Length-at)throw new IOException("handshake write");at+=n;}if(time.ElapsedMilliseconds>=120000)throw new TimeoutException();}
  public static string Admit(ITransport t,string binding,string priorNonce,bool reconnect,string experiment){
   if(!Regex.IsMatch(binding,@"\A[0-9a-f]{64}\z"))throw new ArgumentException();
   if(experiment!="pc-admission-only"&&experiment!="pc-wall-pc")throw new ArgumentException();
   string tag=reconnect?"M15RETURN1":"M15NATIVE1";
   var m=Regex.Match(Line(t,120000),@"\A"+tag+@" ([0-9a-f]{32}) ([0-9a-f]{64}) (pc-admission-only|pc-wall-pc)\z");
   if(!m.Success||m.Groups[1].Value==new string('0',32)||m.Groups[2].Value!=binding||m.Groups[3].Value!=experiment||(reconnect&&m.Groups[1].Value!=priorNonce))throw new InvalidDataException("native admission binding");
   t.Reconcile();Send(t,(reconnect?"M15PC2 ":"M15PC1 ")+m.Groups[1].Value+" "+binding+"\n");return m.Groups[1].Value;
  }
  public static void Terminal(ITransport t,string expectedAck,string path){
   if(!Regex.IsMatch(expectedAck,@"\AM15ACK1 [0-9a-f]{32} [0-9a-f]{64} [0-9a-f]{64}\n\z"))throw new InvalidDataException("terminal expected ACK");
   string expected="M15DONE1 "+expectedAck.Substring(8).TrimEnd('\n');
   if(Line(t,30000)!=expected)throw new InvalidDataException("terminal binding");
   t.Reconcile();Save(path,Encoding.ASCII.GetBytes(expected+"\n"));
  }
  public static void Save(string path,byte[] bytes){using(var f=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None)){f.Write(bytes,0,bytes.Length);f.Flush(true);}}
 }
}
