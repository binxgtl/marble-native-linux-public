// SPDX-License-Identifier: GPL-2.0-only
using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Diagnostics;
namespace M15Offline {
 public static class PcSmoke {
  public static void VerifyBinding(string path,string nonce,string binding) {
   byte[] expected=Encoding.ASCII.GetBytes("M15E1 "+nonce+" "+binding+" 6\n");
   using(var f=File.OpenRead(path)){
    foreach(byte b in expected)if(f.ReadByte()!=b)throw new InvalidDataException("capture/admission mismatch");
   }
  }
  // Explicit transport-only handshake; metadata binding must come from reviewed
  // local inventory, never learn-and-trust the value offered by the device.
  public static string Admit(ITransport t,string expected,int deadlineMs) {
   if(!Regex.IsMatch(expected,@"\A[0-9a-f]{64}\z")||deadlineMs<1||deadlineMs>300000)throw new ArgumentException();
   var clock=Stopwatch.StartNew();var line=new StringBuilder();byte[] b=new byte[1];
   while(true){
    if(clock.ElapsedMilliseconds>=deadlineMs)throw new TimeoutException();
    if(t.Read(b)!=1)throw new IOException("admission disconnect");
    if(b[0]==10)break;
    if(b[0]<32||b[0]>126||line.Length>=128)throw new InvalidDataException("admission framing");
    line.Append((char)b[0]);
   }
   var m=Regex.Match(line.ToString(),@"\AM15PCSMOKE1 ([0-9a-f]{32}) ([0-9a-f]{64})\z");
   if(!m.Success||m.Groups[1].Value==new string('0',32)||m.Groups[2].Value!=expected)throw new InvalidDataException("admission binding");
   t.Reconcile();byte[] ack=Encoding.ASCII.GetBytes("M15PC1 "+m.Groups[1].Value+" "+expected+"\n");
   for(int at=0;at<ack.Length;){
    if(clock.ElapsedMilliseconds>=deadlineMs)throw new TimeoutException();
    int n=t.Write(ack,at,ack.Length-at);if(n<=0||n>ack.Length-at)throw new IOException("admission short write");at+=n;
   }
   return m.Groups[1].Value;
  }
 }
}
