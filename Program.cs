using System;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

class Program
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    struct IcmpHeader
    {
        public byte Type;
        public byte Code;
        public ushort Checksum;
        public ushort Id;
        public ushort Seq;
    }

    static void Error(string msg)
    {
        Console.Error.WriteLine(msg);
        Environment.Exit(1);
    }

    static ushort IpChecksum(byte[] buf, int length)
    {
        uint sum = 0;
        int i = 0;

        while (length > 1)
        {
            ushort word = (ushort)((buf[i] << 8) | buf[i + 1]);
            sum += word;
            i += 2;
            length -= 2;
        }

        if (length == 1)
        {
            ushort odd = (ushort)(buf[i] << 8);
            sum += odd;
        }

        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);

        return (ushort)~sum;
    }

    static void Main(string[] args)
    {
        if (args.Length != 1)
        {
            Console.WriteLine("Usage: mytraceroute <target_ip>");
            return;
        }

        string target = args[0];

        if (!IPAddress.TryParse(target, out IPAddress destIp))
        {
            Error("Target must be IPv4 address (no DNS names allowed)");
        }

        try
        {
            Socket sock = new Socket(AddressFamily.InterNetwork,
                                     SocketType.Raw,
                                     ProtocolType.Icmp);

            IPEndPoint destEndPoint = new IPEndPoint(destIp, 0);

            const int maxHops = 30;
            const int probes = 3;
            ushort pid = (ushort)System.Diagnostics.Process.GetCurrentProcess().Id;

            Console.WriteLine($"\nmytraceroute (ICMP/raw) to {destIp}, {maxHops} hops max");

            byte[] sendBuf = new byte[64];
            byte[] recvBuf = new byte[1024];
            bool reached = false;

            for (int ttl = 1; ttl <= maxHops && !reached; ++ttl)
            {
                Console.Write($"{ttl,2}  ");
                bool printedIp = false;

                for (int probe = 0; probe < probes; ++probe)
                {

                    sock.SetSocketOption(SocketOptionLevel.IP,
                                         SocketOptionName.IpTimeToLive,
                                         ttl);

                    Array.Clear(sendBuf, 0, sendBuf.Length);

                    IcmpHeader hdr = new IcmpHeader
                    {
                        Type = 8,
                        Code = 0,
                        Checksum = 0,
                        Id = (ushort)IPAddress.HostToNetworkOrder((short)pid),
                        Seq = (ushort)IPAddress.HostToNetworkOrder(
                                        (short)((ttl << 8) | probe))
                    };

                    int hdrSize = Marshal.SizeOf<IcmpHeader>();
                    IntPtr ptr = Marshal.AllocHGlobal(hdrSize);
                    Marshal.StructureToPtr(hdr, ptr, false);
                    Marshal.Copy(ptr, sendBuf, 0, hdrSize);
                    Marshal.FreeHGlobal(ptr);

                    int dataLen = 32;
                    for (int i = 0; i < dataLen; i++)
                        sendBuf[hdrSize + i] = (byte)'X';

                    int icmpLen = hdrSize + dataLen;

                    ushort checksum = IpChecksum(sendBuf, icmpLen);
                    sendBuf[2] = (byte)(checksum >> 8);
                    sendBuf[3] = (byte)(checksum & 0xFF);

                    EndPoint fromEp = new IPEndPoint(IPAddress.Any, 0);

                    var sw = System.Diagnostics.Stopwatch.StartNew();

                    try
                    {
                        sock.SendTo(sendBuf, 0, icmpLen, SocketFlags.None, destEndPoint);
                    }
                    catch
                    {
                        Console.Write("E ");
                        continue;
                    }


                    sock.ReceiveTimeout = 3000;
                    int received;
                    try
                    {
                        received = sock.ReceiveFrom(recvBuf, ref fromEp);
                    }
                    catch (SocketException ex) when (ex.SocketErrorCode == SocketError.TimedOut)
                    {
                        Console.Write("* ");
                        continue;
                    }
                    catch
                    {
                        Console.Write("E ");
                        continue;
                    }

                    sw.Stop();
                    double rtt = sw.Elapsed.TotalMilliseconds;


                    if (received < 20 + 8)
                    {
                        Console.Write("E ");
                        continue;
                    }

                    int ipHeaderLen = (recvBuf[0] & 0x0F) * 4;
                    if (received < ipHeaderLen + 8)
                    {
                        Console.Write("E ");
                        continue;
                    }

                    byte icmpType = recvBuf[ipHeaderLen + 0];
                    byte icmpCode = recvBuf[ipHeaderLen + 1];

                    if (!printedIp)
                    {
                        var fromIp = ((IPEndPoint)fromEp).Address;
                        Console.Write($"{fromIp}  ");
                        printedIp = true;
                    }

                    Console.Write($"{rtt:0.###} ms ");

                    if (icmpType == 0 && icmpCode == 0)
                        reached = true;
                }

                Console.WriteLine();
            }

            sock.Close();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex);
        }
    }
}
