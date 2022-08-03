using Bitmessage.Global;
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;

namespace Bitmessage.Storage
{
    public class BitmessagePeer
    {
        public DateTime LastAttempt { get; set; }

        public bool LastSuccess { get; set; }

        public IPEndPoint Address { get; set; }

        public BitmessagePeer()
        {

        }

        public BitmessagePeer(IPEndPoint EP)
        {
            LastAttempt = DateTime.UtcNow;
            LastSuccess = false;
            Address = EP;
        }

        public void Serialize(Stream Output)
        {
            using var BW = Output.GetWriter();
            BW.Write(Tools.ToUnixTime(LastAttempt));
            BW.Write(LastSuccess);
            var Addr = Address.Address;
            if (Addr.AddressFamily == AddressFamily.InterNetworkV6)
            {
                BW.Write(Addr.GetAddressBytes());
            }
            else
            {
                BW.Write(Addr.MapToIPv6().GetAddressBytes());
            }
            BW.Write((ushort)Address.Port);
        }

        public static BitmessagePeer Deserialize(Stream Input)
        {
            var P = new BitmessagePeer();
            using var BR = Input.GetReader();
            P.LastAttempt = Tools.FromUnixTime(BR.ReadUInt64());
            P.LastSuccess = BR.ReadBool();
            var Addr = new IPAddress(BR.ReadBytes(16));
            if (Addr.IsIPv4MappedToIPv6)
            {
                Addr = Addr.MapToIPv4();
            }
            P.Address = new IPEndPoint(Addr, BR.ReadUInt16());
            return P;
        }
    }
}
