using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Runtime.Remoting.Messaging;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace 流量监控
{
    [StructLayout(LayoutKind.Explicit)]
    public struct IPHeader
    {
        [FieldOffset(0)] public byte ip_verlen; //I4位首部长度+4位IP版本号 
        [FieldOffset(1)] public byte ip_tos; //8位服务类型TOS 
        [FieldOffset(2)] public ushort ip_totallength; //16位数据包总长度（字节） 
        [FieldOffset(4)] public ushort ip_id; //16位标识 
        [FieldOffset(6)] public ushort ip_offset; //3位标志位 
        [FieldOffset(8)] public byte ip_ttl; //8位生存时间 TTL 
        [FieldOffset(9)] public byte ip_protocol; //8位协议(TCP, UDP, ICMP, Etc.) 
        [FieldOffset(10)] public ushort ip_checksum; //16位IP首部校验和 
        [FieldOffset(12)] public uint ip_srcaddr; //32位源IP地址 
        [FieldOffset(16)] public uint ip_destaddr; //32位目的IP地址 
    }
    [StructLayout(LayoutKind.Explicit)]
    public struct IPHeader2
    {
        [FieldOffset(0)] public byte ip_verlen; //I4位首部长度+4位IP版本号 
        [FieldOffset(1)] public byte ip_tos; //8位服务类型TOS 
        [FieldOffset(2)] public ushort ip_totallength; //16位数据包总长度（字节） 
        [FieldOffset(4)] public ushort ip_id; //16位标识 
        [FieldOffset(6)] public ushort ip_offset; //3位标志位 
        [FieldOffset(8)] public byte ip_ttl; //8位生存时间 TTL 
        [FieldOffset(9)] public byte ip_protocol; //8位协议(TCP, UDP, ICMP, Etc.) 
        [FieldOffset(10)] public ushort ip_checksum; //16位IP首部校验和 
        [FieldOffset(12)] public uint ip_srcaddr; //32位源IP地址 
        [FieldOffset(16)] public uint ip_destaddr; //32位目的IP地址 
        [FieldOffset(20)] public ushort sport;//16位源端口 
        [FieldOffset(22)] public ushort dport;//16位目的端口  
    }
    public struct tsd_hdr//定义TCP伪首部  
    {
        public ulong saddr;//源地址  
        public ulong daddr;//目的地址  
        public char mbz;
        public char ptcl;//协议类型  
        public ushort tcpl;//TCP长度  
    }

    unsafe public struct tcp_hdr//定义TCP首部  
    {
        public ushort sport;//16位源端口  
        public ushort dport;//16位目的端口  
        public uint seq;//32位序列号  
        public uint ack;//32位确认号  
        public char* lenres;//4位首部长度/6位保留字  
        public char* flag;//6位标志位  
        public ushort win;//16位窗口大小  
        public ushort sum;//16位检验和  
        public ushort urp;//16位紧急数据偏移量  
    }
    [StructLayout(LayoutKind.Explicit)]
    public struct udp_hdr//定义UDP首部  
    {
        [FieldOffset(0)] public ushort sport;//16位源端口  
        [FieldOffset(2)] public ushort dport;//16位目的端口  
        [FieldOffset(4)] public ushort len;//UDP 长度  
        [FieldOffset(6)] public ushort cksum;//检查和  
    }
    public struct icmp_hdr//定义ICMP首部  
    {
        public ushort sport;
        public ushort dport;
        public char type;
        public char code;
        public ushort cksum;
        public ushort id;
        public ushort seq;
        public ulong timestamp;
    }
    public class RawSocket
    {
        /// <summary>
        /// 是否产生错误
        /// </summary>
        private bool error_occurred;
        /// <summary>
        /// 是否继续进行
        /// </summary>
        public bool KeepRunning = true;
        /// <summary>
        /// 得到的数据流的长度
        /// 定值
        /// </summary>
        private static int len_receive_buf;
        /// <summary>
        /// 收到的字节
        /// </summary>
        byte[] receive_buf_bytes;
        /// <summary>
        /// 声明套接字
        /// </summary>
        private Socket socket = null;
        /// <summary>
        /// 常量
        /// </summary>
        const int SIO_R = unchecked((int)0x98000001);
        /// <summary>
        /// 常量
        /// </summary>
        const int SIO_1 = unchecked((int)0x98000002);
        /// <summary>
        /// 常量
        /// </summary>
        const int SIO_2 = unchecked((int)0x98000003);
        public int Threads = 2;
        /// <summary>
        /// 构造函数
        /// </summary>
        public RawSocket(RawSocketType type)
        {
            if (type == RawSocketType.Listen) { }
            else if (type == RawSocketType.Connet) { }
            len_receive_buf = 4096;
            receive_buf_bytes = new byte[4096];
        }
        /// <summary>
        /// 建立并绑定套接字
        /// </summary>
        /// <param name="IP">IP地址</param>
        public void CreateAndBindSocket(IPAddress IP, int port)
        {
            socket = new Socket(IP.AddressFamily, SocketType.Raw, ProtocolType.IP);
            socket.Blocking = true;//置socket非阻塞状态
            socket.Bind(new IPEndPoint(IP, port));
            if (SetSocketOption() == false) error_occurred = true;
        }
        /// <summary>
        /// 关闭原始套接字
        /// </summary>
        public void Shutdown()
        {
            if (socket != null)
            {
                socket.Shutdown(SocketShutdown.Both);
                socket.Close();
            }
        }

        private bool SetSocketOption()
        {
            bool ret_value = true;
            try
            {
                socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, 1);
                byte[] IN = new byte[4] { 1, 0, 0, 0 };
                byte[] OUT = new byte[4];
                int ret_code = socket.IOControl(SIO_R, IN, OUT);//低级别操作模式
                ret_code = OUT[0] + OUT[1] + OUT[2] + OUT[3];//把4个8位字节合成一个32位整数
                if (ret_code != 0) ret_value = false;
            }
            catch (SocketException)
            {
                ret_value = false;
            }
            return ret_value;
        }
        /// <summary>
        /// 返回是否出错
        /// </summary>
        public bool ErrorOccurred
        {
            get
            {
                return error_occurred;
            }
        }
        /// <summary>
        /// 解析接收的数据包，形成PacketArrivedEventArgs时间数据类对象，并引发PacketArrival事件
        /// </summary>
        /// <param name="buf"></param>
        /// <param name="len"></param>
        unsafe private void Receive(byte[] buf, int len)
        {
            byte temp_protocol = 0;
            uint temp_version = 0;
            uint temp_ip_srcaddr = 0;
            uint temp_ip_destaddr = 0;
            short temp_srcport = 0;
            short temp_dstport = 0;
            IPAddress temp_ip;
            PacketArrivedEventArgs e = new PacketArrivedEventArgs();
            udp_hdr* pUdpheader;//UDP头结构体指针  
            IPHeader* head;//IP头结构体指针  
            tcp_hdr* pTcpheader;//TCP头结构体指针  
            icmp_hdr* pIcmpheader;//ICMP头结构体指针 
            IPHeader2* Portheader;//端口指针
            fixed (byte* fixed_buf = buf)
            {
                int lentcp, lenudp, lenicmp, lenip;
                head = (IPHeader*)fixed_buf;//IP头结构体指针  
                Portheader = (IPHeader2*)fixed_buf;
                pTcpheader = (tcp_hdr*)(fixed_buf + sizeof(IPHeader)); //TCP头结构体指针 
                pUdpheader = (udp_hdr*)(fixed_buf + sizeof(IPHeader));
                pIcmpheader = (icmp_hdr*)(fixed_buf + sizeof(IPHeader));
                //计算各种包的长度（只有判断是否是该包后才有意义，先计算出来）
                lenip = ntohs(head->ip_totallength);
                try
                {
                    lentcp = ntohs(head->ip_totallength) - (sizeof(IPHeader) + sizeof(tcp_hdr));
                    lenudp = ntohs(head->ip_totallength) - (sizeof(IPHeader) + sizeof(udp_hdr));
                    lenicmp = ntohs(head->ip_totallength) - (sizeof(IPHeader) + sizeof(icmp_hdr));
                }
                catch { }
                e.HeaderLength = (uint)(head->ip_verlen & 0x0F) << 2;
                temp_protocol = head->ip_protocol;
                temp_dstport = *(short*)&fixed_buf[e.HeaderLength + 2];
                switch (temp_protocol)
                {
                    case 1: e.Protocol = "ICMP:"; break;
                    case 2: e.Protocol = "IGMP:"; break;
                    case 6: e.Protocol = "TCP:"; e.DestinationPort = ntohs(pTcpheader->dport).ToString(); break;
                    case 17: e.Protocol = "UDP:"; e.DestinationPort = ntohs(pUdpheader->dport).ToString(); break;
                    default: e.Protocol = "UNKNOWN"; break;
                }
                temp_version = (uint)(head->ip_verlen & 0xF0) >> 4;
                e.IPVersion = temp_version.ToString();
                temp_ip_srcaddr = head->ip_srcaddr;
                temp_ip_destaddr = head->ip_destaddr;
                temp_ip = new IPAddress(temp_ip_srcaddr);
                e.OriginationAddress = temp_ip.ToString();
                temp_ip = new IPAddress(temp_ip_destaddr);
                e.DestinationAddress = temp_ip.ToString();
                temp_srcport = *(short*)&fixed_buf[e.HeaderLength];
                e.OriginationPort = ntohs(Portheader->sport).ToString();
                int acb = IPAddress.NetworkToHostOrder(Portheader->sport);
                e.DestinationPort = ntohs(Portheader->dport).ToString();
                int abc = IPAddress.NetworkToHostOrder(Portheader->dport);
                e.PacketLength = (uint)lenip;
                e.MessageLength = (uint)lenip - e.HeaderLength;
                e.ReceiveBuffer = buf;
                //把buf中的IP头赋给PacketArrivedEventArgs中的IPHeaderBuffer
                Array.Copy(buf, 0, e.IPHeaderBuffer, 0, (int)e.HeaderLength);
                //把buf中的包中内容赋给PacketArrivedEventArgs中的MessageBuffer
                Array.Copy(buf, (int)e.HeaderLength, e.MessageBuffer, 0, (int)e.MessageLength);
            }
            //引发PacketArrival事件
            OnPacketArrival(e);
        }
        public void Run()
        {
            KeepRunning = true;
            socket.ReceiveBufferSize = 1024 * 1024 * 10;
            for (int i = 0; i < Threads; i++)
            {
                Thread thread = new Thread(new ThreadStart(() =>
                {
                    while (KeepRunning)
                    {
                        int received_bytes = -1;
                        byte[] Buffer = new byte[65535];
                        try
                        {
                            received_bytes = socket.Receive(Buffer, 0, 65535, SocketFlags.None);
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine(e.Message);
                            KeepRunning = false;
                        }
                        if (received_bytes > 0)
                            Receive(Buffer, received_bytes);
                    }
                }));
                thread.IsBackground = true;
                thread.Start();
                Thread.Sleep(100);
                Console.WriteLine("IP：" + socket.LocalEndPoint.ToString() + " 数据包接收线程： " + i + "已启动");
            }
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("抓包线程分配完毕");
            Console.ResetColor();
            //IAsyncResult ar = socket.BeginReceive(receive_buf_bytes, 0, len_receive_buf, SocketFlags.None, new AsyncCallback(CallReceive), this);
        }

        private void CallReceive(IAsyncResult ar)
        {
            int received_bytes;
            received_bytes = receive_buf_bytes.Length;
            Receive(receive_buf_bytes, received_bytes);
            if (KeepRunning) Run();
        }
        public int ntohs(ushort n)
        {
            byte[] b = BitConverter.GetBytes(n);
            Array.Reverse(b);
            return (int)BitConverter.ToInt16(b, 0);
        }

        public class PacketArrivedEventArgs : EventArgs
        {
            public PacketArrivedEventArgs()
            {
                this.protocol = "";
                this.destination_port = "";
                this.origination_port = "";
                this.destination_address = "";
                this.origination_address = "";
                this.ip_version = "";

                this.total_packet_length = 0;
                this.message_length = 0;
                this.header_length = 0;

                this.receive_buf_bytes = new byte[len_receive_buf];
                this.ip_header_bytes = new byte[len_receive_buf];
                this.message_bytes = new byte[len_receive_buf];
            }
            /// <summary>
            /// 数据包协议类型
            /// </summary>
            public string Protocol
            {
                get { return protocol; }
                set { protocol = value; }
            }
            /// <summary>
            /// 目标端口
            /// </summary>
            public string DestinationPort
            {
                get { return destination_port; }
                set { destination_port = value; }
            }
            /// <summary>
            /// 源端口
            /// </summary>
            public string OriginationPort
            {
                get { return origination_port; }
                set { origination_port = value; }
            }
            /// <summary>
            /// 目标IP
            /// </summary>
            public string DestinationAddress
            {
                get { return destination_address; }
                set { destination_address = value; }
            }
            /// <summary>
            /// 源IP
            /// </summary>
            public string OriginationAddress
            {
                get { return origination_address; }
                set { origination_address = value; }
            }
            /// <summary>
            /// IP版本
            /// </summary>
            public string IPVersion
            {
                get { return ip_version; }
                set { ip_version = value; }
            }
            /// <summary>
            /// 数据包长度
            /// </summary>
            public uint PacketLength
            {
                get { return total_packet_length; }
                set { total_packet_length = value; }
            }
            /// <summary>
            /// 消息长度
            /// </summary>
            public uint MessageLength
            {
                get { return message_length; }
                set { message_length = value; }
            }
            /// <summary>
            /// 头部长度
            /// </summary>
            public uint HeaderLength
            {
                get { return header_length; }
                set { header_length = value; }
            }/// <summary>
             /// 接收的缓存
             /// </summary>
            public byte[] ReceiveBuffer
            {
                get { return receive_buf_bytes; }
                set { receive_buf_bytes = value; }
            }
            /// <summary>
            /// IP头部缓存
            /// </summary>
            public byte[] IPHeaderBuffer
            {
                get { return ip_header_bytes; }
                set { ip_header_bytes = value; }
            }
            /// <summary>
            /// 消息缓存
            /// </summary>
            public byte[] MessageBuffer
            {
                get { return message_bytes; }
                set { message_bytes = value; }
            }
            private string protocol;
            private string destination_port;
            private string origination_port;
            private string destination_address;
            private string origination_address;
            private string ip_version;
            public uint total_packet_length;
            private uint message_length;
            private uint header_length;
            private byte[] receive_buf_bytes = null;
            private byte[] ip_header_bytes = null;
            private byte[] message_bytes = null;
        }

        public delegate void PacketArrivedEventHandler(
         Object sender, PacketArrivedEventArgs args);

        public event PacketArrivedEventHandler PacketArrival;

        protected virtual void OnPacketArrival(PacketArrivedEventArgs e)
        {
            if (PacketArrival != null)
            {
                PacketArrival(this, e);
            }
        }
    }
    public enum RawSocketType
    {
        /// <summary>
        /// 设置为窃听模式
        /// </summary>
        Listen,
        /// <summary>
        /// 设置为通信模式
        /// 需要指定网络终结点
        /// </summary>
        Connet,
        /// <summary>
        /// 指定端口的窃听模式
        /// </summary>
        PortListen
    }
}