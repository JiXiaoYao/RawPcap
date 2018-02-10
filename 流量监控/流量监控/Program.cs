using System;
using System.Collections.Generic;
using System.Linq;
using System.Diagnostics;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using static 流量监控.RawSocket;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;

namespace 流量监控
{
    class Program
    {
        static long Length = 0;
        static long Out = 0;
        static long In = 0;
        static int TCP = 0;
        static int UDP = 0;
        static int ICMP = 0;
        static int IGMP = 0;
        static int UNKNOWN = 0;
        static int Port = 0;
        static IPAddress[] iPAddress;
        static List<string> Log = new List<string>();
        static long AllOut = 0;
        static long AllIn = 0;
        static void Main(string[] args)
        {
            if (!Directory.Exists(AppDomain.CurrentDomain.BaseDirectory + "Log"))
                Directory.CreateDirectory(AppDomain.CurrentDomain.BaseDirectory + "Log");
            Port = 25565;
            Console.WriteLine("本机IP地址如下：");
            iPAddress = Dns.GetHostAddresses(Dns.GetHostName());
            for (int i = 0; i < iPAddress.Length; i++)
                if (iPAddress[i].AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) Console.WriteLine("{" + i + "}  IP协议版本：" + iPAddress[i].AddressFamily.ToString() + "V4  地址：" + iPAddress[i].ToString());
                else Console.WriteLine("{" + i + "}  IP协议版本：" + iPAddress[i].AddressFamily.ToString() + "  地址：" + iPAddress[i].ToString());
            cIP: Console.WriteLine("请选择IP,多选使用';'隔开\r\n输入*为全部抓包");
            string IPB = Console.ReadLine();
            string[] IPBuffer = IPB.Split(';');
            List<int> IPID = new List<int>();
            if (IPB == "*")
                for (int i = 0; i < iPAddress.Length; i++)
                    IPID.Add(i);
            else
                for (int i = 0; i < IPBuffer.Length; i++)
                {
                    int result;
                    if (!int.TryParse(IPBuffer[i], out result)) { Console.ForegroundColor = ConsoleColor.Red; Console.WriteLine("输入有误"); Console.ResetColor(); goto cIP; }
                    else if (iPAddress.Length <= result || result < 0) { Console.ForegroundColor = ConsoleColor.Red; Console.WriteLine("目标IP不存在"); Console.ResetColor(); goto cIP; }
                    else { IPID.Add(result); }
                }
            cPort: Console.WriteLine("请输入端口");
            try { Port = int.Parse(Console.ReadLine()); } catch { Console.WriteLine("输入字符串有误\r\n请重新输入");goto cPort; }
            if (Port < 1 || Port > 65535) { Console.ForegroundColor = ConsoleColor.Red; Console.WriteLine("输入有误"); Console.ResetColor(); goto cPort; }
            cTh: Console.WriteLine("请输入每个套接字要设置的抓包线程\r\n线程越多越灵敏\r\n由于设置套接字为阻塞模式\r\n所以不会占用过多CPU资源\r\n不清楚电脑网络情况的可以设置20线程\r\n不进行大流量操作的可以设置10线程");
            int Threads = int.Parse(Console.ReadLine());
            if (Threads < 2 || Threads > 1000) { Console.ForegroundColor = ConsoleColor.Red; Console.WriteLine("输入有误，最小2线程最大1000线程！"); Console.ResetColor(); goto cTh; }
            Thread thread = new Thread(new ThreadStart(() =>
            {
                while (true)
                    if (Console.ReadKey().Modifiers == ConsoleModifiers.Control && Console.ReadKey().Key == ConsoleKey.S)
                    {
                        File.AppendAllLines(AppDomain.CurrentDomain.BaseDirectory + "log/" + DateTime.Now.Year + "." + DateTime.Now.Month + "." + DateTime.Now.Day + ".last.log", Log.AsEnumerable());
                        Log = new List<string>();
                    }
            }));
            thread.IsBackground = true;
            thread.Start();
            for (int i = 0; i < IPID.Count; i++)
            {
                RawSocket rawSocket = new RawSocket(RawSocketType.Listen);
                rawSocket.PacketArrival += Pack;
                rawSocket.CreateAndBindSocket(iPAddress[IPID[i]], 0);
                rawSocket.Threads = Threads;
                rawSocket.Run();
            }
            Thread.Sleep(100);
            long Last = 0;
            long OutLast = 0;
            long alloutLast = 0;
            long allinLast = 0;
            long inLast = 0;
            Stopwatch stopwatch = new Stopwatch();
            SetConsoleCtrlHandler(cancelHandler, true);
            stopwatch.Start();
            while (true)
            {
                Thread.Sleep(1000);
                double length = Length - Last;         // 计算总流量
                double outlength = Out - OutLast;      // 计算监控端口出站流量
                double allout = AllOut - alloutLast;   // 计算出站总流量
                double allin = AllIn - allinLast;      // 计算入站总流量
                double IN = In - inLast;               // 计算监控端口入站流量
                stopwatch.Stop();
                Last = Length;
                OutLast = Out;
                alloutLast = AllOut;
                allinLast = AllIn;
                inLast = In;
                length = length / stopwatch.Elapsed.TotalSeconds;
                outlength = outlength / stopwatch.Elapsed.TotalSeconds;
                allout = allout / stopwatch.Elapsed.TotalSeconds;
                allin = allin / stopwatch.Elapsed.TotalSeconds;
                IN = IN / stopwatch.Elapsed.TotalSeconds;
                stopwatch.Restart();
                // Console.Clear();
                string OutPut = "*************************************************************\r\n";
                OutPut = OutPut + "%     数据名称      |        数据       |        单位       %\r\n";
                OutPut = OutPut + "*************************************************************\r\n";//GetLegth(.Length)
                OutPut = OutPut + "当前时间：" + DateTime.Now + "\r\n";
                OutPut = OutPut + "端口：                      " + Port + GetLegth(Port.ToString().Length) + "\r\n";
                OutPut = OutPut + "总流量：                    " + GetSpand(Length, false) + "\r\n";
                OutPut = OutPut + "出站总流量：                " + GetSpand(AllOut, false) + "\r\n";
                OutPut = OutPut + "入站总流量：                " + GetSpand(AllIn, false) + "\r\n";
                OutPut = OutPut + "总速度：                    " + GetSpand(length, false) + "/s\r\n";
                OutPut = OutPut + "总位速度：                  " + GetSpand(length * 8, true) + "\r\n";
                OutPut = OutPut + "出站位速度：                " + GetSpand(allout * 8, true) + "\r\n";
                OutPut = OutPut + "入站位速度：                " + GetSpand(allin * 8, true) + "\r\n";
                OutPut = OutPut + "监控目标总流量：            " + GetSpand(Out + In, false) + "\r\n";
                OutPut = OutPut + "监控目标出站总流量：        " + GetSpand(Out, false) + "\r\n";
                OutPut = OutPut + "监控目标入站总流量：        " + GetSpand(In, false) + "\r\n";
                OutPut = OutPut + "监控目标出站总速度：        " + GetSpand(outlength * 8, true) + "\r\n";
                OutPut = OutPut + "监控目标入站总速度：        " + GetSpand(IN * 8, true) + "\r\n";
                Console.Clear();
                Console.Write(OutPut);
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("数据包统计: TCP：" + TCP + "个   UDP：" + UDP + "个   ICMP：" + ICMP + "个   IGMP：" + IGMP + "个   UNKNOWN：" + UNKNOWN + "个");
                Console.ResetColor();
                Log.Add("[" + DateTime.Now.ToLongTimeString() + "]" + Out);
                if (DateTime.Now.Hour == 0 && DateTime.Now.Minute == 0 && DateTime.Now.Second < 10)
                {
                    if (!File.Exists(AppDomain.CurrentDomain.BaseDirectory + "log/" + DateTime.Now.Year + "." + DateTime.Now.Month + "." + DateTime.Now.Day + ".log"))
                    {
                        string[] LogBuffer = { };
                        if (File.Exists(AppDomain.CurrentDomain.BaseDirectory + "log/" + DateTime.Now.Year + "." + DateTime.Now.Month + "." + DateTime.Now.Day + ".last.log"))
                        {
                            LogBuffer = File.ReadAllLines(AppDomain.CurrentDomain.BaseDirectory + "log/" + DateTime.Now.Year + "." + DateTime.Now.Month + "." + DateTime.Now.Day + ".last.log");
                        }
                        if (LogBuffer.Length > 0)
                        {
                            File.WriteAllLines(AppDomain.CurrentDomain.BaseDirectory + "/log/" + DateTime.Now.Year + "." + DateTime.Now.Month + "." + DateTime.Now.Day + ".log", LogBuffer);
                            File.AppendAllLines(AppDomain.CurrentDomain.BaseDirectory + "/log/" + DateTime.Now.Year + "." + DateTime.Now.Month + "." + DateTime.Now.Day + ".log", Log.AsEnumerable());
                        }
                        else
                            File.WriteAllLines(AppDomain.CurrentDomain.BaseDirectory + "/log/" + DateTime.Now.Year + "." + DateTime.Now.Month + "." + DateTime.Now.Day + ".log", Log.ToArray());
                        Log = new List<string>();
                    }
                }
            }
            // Console.ReadLine();
        }
        public delegate bool ControlCtrlDelegate(int CtrlType);
        [DllImport("kernel32.dll")]
        private static extern bool SetConsoleCtrlHandler(ControlCtrlDelegate HandlerRoutine, bool Add);
        private static ControlCtrlDelegate cancelHandler = new ControlCtrlDelegate(HandlerRoutine);

        public static bool HandlerRoutine(int CtrlType)
        {
            switch (CtrlType)
            {
                case 0:
                    File.AppendAllLines(AppDomain.CurrentDomain.BaseDirectory + "log/" + DateTime.Now.Year + "." + DateTime.Now.Month + "." + DateTime.Now.Day + ".last.log", Log.AsEnumerable()); //Ctrl+C关闭
                    break;
                case 2:
                    File.AppendAllLines(AppDomain.CurrentDomain.BaseDirectory + "log/" + DateTime.Now.Year + "." + DateTime.Now.Month + "." + DateTime.Now.Day + ".last.log", Log.AsEnumerable());//按控制台关闭按钮关闭
                    break;
            }
            return false;
        }
        static public void Pack(Object sender, PacketArrivedEventArgs args)
        {
            //Console.Clear();
            Length = Length + args.PacketLength;
            if (args.Protocol == "TCP:")
                TCP++;
            if (args.Protocol == "UDP:")
                UDP++;
            if (args.Protocol == "ICMP:")
                ICMP++;
            if (args.Protocol == "IGMP:")
                IGMP++;
            if (args.Protocol == "UNKNOWN")
                UNKNOWN++;
            //if (args.OriginationPort == Port.ToString() && iPAddress.Contains(IPAddress.Parse(args.OriginationAddress)))
            //    Out = Out + args.PacketLength;
            //if (args.DestinationPort == Port.ToString() && iPAddress.Contains(IPAddress.Parse(args.DestinationAddress)))
            //In = In + args.PacketLength;
            if (iPAddress.Contains(IPAddress.Parse(args.OriginationAddress)))
            {
                AllOut = AllOut + args.PacketLength;
                if (args.OriginationPort == Port.ToString())
                    Out = Out + args.PacketLength;
            }
            else
            {
                AllIn = AllIn + args.PacketLength;
                if (args.DestinationPort == Port.ToString())
                {
                    In = In + args.PacketLength;
                }
            }
            //Console.WriteLine("目标IP：" + args.DestinationAddress);
            //Console.WriteLine("目标端口：" + args.DestinationPort);
            //Console.WriteLine("IP协议版本：" + args.IPVersion);
            //Console.WriteLine("目标地址：" + args.OriginationAddress);
            //Console.WriteLine("目标端口：" + args.OriginationPort);
            //Console.WriteLine("数据包长度" + args.PacketLength);
            //Console.WriteLine("协议：" + args.Protocol);
            //Console.WriteLine("已接收字节数：" + Length);
            //Console.WriteLine(GetSpand(Length));
        }
        static public string GetSpand(double Length, bool IsBit)
        {
            if (IsBit)
            {
                if (Length < 1024)
                    return Length.ToString("0.000") + GetLegth(Length.ToString("0.000").Length) + "Bps";
                else if (Length > 1024 && Length < (1024 * 1024))
                    return (Length / (1024)).ToString("0.000") + GetLegth((Length / (1024)).ToString("0.000").Length) + "Kbps";
                else if (Length > (1024 * 1024) && Length < (1024 * 1024 * 1024))
                    return (Length / (1024 * 1024)).ToString("0.000") + GetLegth((Length / (1024 * 1024)).ToString("0.000").Length) + "Mbps";
                else
                    return (Length / (1024 * 1024 * 1024)).ToString("0.000") + GetLegth((Length / (1024 * 1024 * 1024)).ToString("0.000").Length) + "Gbps";
            }
            else
            {
                if (Length < 1024)
                    return Length.ToString("0.000") + GetLegth(Length.ToString("0.000").Length) + "Byte";
                else if (Length > 1024 && Length < (1024 * 1024))
                    return (Length / (1024)).ToString("0.000") + GetLegth((Length / (1024)).ToString("0.000").Length) + "KB";
                else if (Length > (1024 * 1024) && Length < (1024 * 1024 * 1024))
                    return (Length / (1024 * 1024)).ToString("0.000") + GetLegth((Length / (1024 * 1024)).ToString("0.000").Length) + "MB";
                else
                    return (Length / (1024 * 1024 * 1024)).ToString("0.000") + GetLegth((Length / (1024 * 1024 * 1024)).ToString("0.000").Length) + "GB";
            }
        }
        static public string GetLegth(int Length)
        {
            string Return = "";
            for (int i = Length; i < 22; i++) { Return = Return + " "; }
            return Return;
        }
    }
}