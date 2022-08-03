using Bitmessage.Global;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;

namespace Bitmessage.Storage
{
    public class Peers
    {
        /// <summary>
        /// Port numbers considered temporary as per IANA and RFC 6335
        /// </summary>
        /// <remarks>
        /// Many Linux kernels don't think they have to follow best practices
        /// and ephemeral ports often start at 32768 already.
        /// Windows Vista and later follow the RFC, so does BSD.
        /// For linux, check the file "/proc/sys/net/ipv4/ip_local_port_range" for actual range.
        /// </remarks>
        public const int EPHEMERAL_PORT_START = 49152;

        /// <summary>
        /// Default lifetime of an IP address entry
        /// </summary>
        public static readonly TimeSpan DefaultLifetime = TimeSpan.FromHours(3.0);

        public List<BitmessagePeer> KnownNodes { get; }

        /// <summary>
        /// Ignores IP addresses that are private, reserved, or special use
        /// </summary>
        public bool IgnoreLocalAddresses { get; set; }

        /// <summary>
        /// Ignores port entries including and above
        /// <see cref="EPHEMERAL_PORT_START"/>.
        /// These ports are usually temporary.
        /// Bitmessage is almost always run on port 8448 or 8444.
        /// Higher numbers are often the result of:
        /// - NAT without functioning port forwarding
        /// - The user disabling inbound connections
        /// - VPN, proxy, or Tor
        /// </summary>
        public bool IgnoreEphemeralPorts { get; set; }

        public Peers()
        {
            KnownNodes = new List<BitmessagePeer>();
            IgnoreLocalAddresses = true;
            IgnoreEphemeralPorts = true;
        }

        public bool Contains(IPEndPoint EP)
        {
            return KnownNodes.Any(m => m.Address.Equals(EP));
        }

        public bool Add(IPEndPoint EP)
        {
            var Item = KnownNodes.FirstOrDefault(m => m.Address.Equals(EP));
            //Poke entry if it continues to get advertised
            if (Item != null)
            {
                Item.LastAttempt = DateTime.UtcNow;
                return false;
            }
            KnownNodes.Add(new BitmessagePeer(EP));
            return true;
        }

        public static Peers Deserialize(Stream Data)
        {
            var P = new Peers();
            using var BR = Data.GetReader();
            var NodeCount = BR.ReadUInt32();
            while (NodeCount-- > 0)
            {
                P.KnownNodes.Add(BitmessagePeer.Deserialize(Data));
            }
            P.PurgeInvalid();
            return P;
        }

        public void Serialize(Stream Output)
        {
            using var BW = Output.GetWriter();
            BW.Write((uint)KnownNodes.Count);
            BW.Flush();
            foreach (var Node in KnownNodes)
            {
                Node.Serialize(Output);
            }
        }

        public void Purge(TimeSpan maxAge)
        {
            KnownNodes.RemoveAll(m => m.LastAttempt.Add(maxAge) < DateTime.UtcNow);
        }

        public int PurgeInvalid()
        {
            int removed = 0;
            //Remove completely invalid addresses
            //This is the fastest check so so this first
            if (IgnoreEphemeralPorts)
            {
                removed += KnownNodes.RemoveAll(m => m.Address.Port >= EPHEMERAL_PORT_START);
            }
            //These are always invalid
            removed += KnownNodes.RemoveAll(m =>
                m.Address.Address.Equals(IPAddress.Any) ||
                m.Address.Address.Equals(IPAddress.IPv6Any) ||
                m.Address.Address.Equals(IPAddress.Broadcast) ||
                IPAddress.IsLoopback(m.Address.Address));
            if (IgnoreLocalAddresses)
            {
                removed += KnownNodes.RemoveAll(m => IsLocalAddress(m.Address.Address));
            }
            return removed;
        }

        public static bool IsLocalAddress(IPAddress Addr)
        {
            if (IPAddress.IsLoopback(Addr) || Addr.IsIPv6LinkLocal)
            {
                return true;
            }
            var Bytes = Addr.IsIPv4MappedToIPv6 ? Addr.MapToIPv4().GetAddressBytes() : Addr.GetAddressBytes();
            //Broadcast only works on the local network
            if (Bytes.All(m => m == 0xFF))
            {
                return true;
            }
            if (Bytes.Length == 4)
            {
                return
                    //127.x.x.x (loopback)
                    Bytes[0] == 127 ||
                    //10.x.x.x (priv)
                    Bytes[0] == 10 ||
                    //100.64.x.x - 100.127.x.x (cgnat)
                    (Bytes[0] == 100 && Bytes[1] >= 64 && Bytes[1] <= 127) ||
                    //172.16.x.x - 172.31.x.x (priv)
                    (Bytes[0] == 172 && Bytes[1] >= 16 && Bytes[1] <= 31) ||
                    //192.168.x.x (priv)
                    (Bytes[0] == 192 && Bytes[1] == 168) ||
                    //169.254.x.x (auto)
                    (Bytes[0] == 169 && Bytes[1] == 254) ||
                    //192.0.0.x (priv)
                    (Bytes[0] == 192 && Bytes[1] == 0 && Bytes[2] == 0) ||
                    //192.0.2.x (documentation)
                    (Bytes[0] == 192 && Bytes[1] == 0 && Bytes[2] == 2) ||
                    //192.88.99.x (reserved)
                    (Bytes[0] == 192 && Bytes[1] == 88 && Bytes[2] == 99) ||
                    //192.1[89].x.x (testing)
                    (Bytes[0] == 198 && (Bytes[1] == 18 || Bytes[1] == 19)) ||
                    //198.51.100 (documentation)
                    (Bytes[0] == 198 && Bytes[1] == 51 && Bytes[2] == 100) ||
                    //203.0.113 (documentation)
                    (Bytes[0] == 203 && Bytes[1] == 0 && Bytes[2] == 113) ||
                    //224.x.x.x - 239.x.x.x (multicast)
                    (Bytes[0] >= 224 && Bytes[0] <= 239) ||
                    //233.252.0.x (documentation)
                    (Bytes[0] == 233 && Bytes[1] == 252 && Bytes[2] == 0) ||
                    //240.x.x.x - 255.x.x.x (reserved)
                    Bytes[0] >= 240;
            }
            //TODO: IPv6
            return false;
        }
    }
}
