using Bitmessage.Global;
using System;
using System.IO;
using System.Net;

namespace Bitmessage.Network.Objects
{
    public class NetworkAddress : INetworkSerializable
    {
        public DateTime Timestamp { get; set; }

        public uint Stream { get; set; }

        public VersionServices Services { get; set; }

        public IPAddress Address { get; set; }

        public ushort Port { get; set; }

        public IPEndPoint Endpoint { get => new IPEndPoint(Address, Port); }

        public void Deserialize(Stream Input, bool FromVersion)
        {
            using var BR = Input.GetReader();
            if (!FromVersion)
            {
                Timestamp = Tools.FromUnixTime(BR.ReadUInt64());
                Stream = BR.ReadUInt32();
            }
            else
            {
                Timestamp = DateTime.UtcNow;
                Stream = 1;
            }
            Services = (VersionServices)BR.ReadUInt64();
            Address = new IPAddress(BR.ReadBytes(16));
            Port = BR.ReadUInt16();
            if (Address.IsIPv4MappedToIPv6)
            {
                Address = Address.MapToIPv4();
            }
        }

        public void Deserialize(Stream Input)
        {
            Deserialize(Input, false);
        }

        public void Serialize(Stream Output)
        {
            Serialize(Output, false);
        }

        public void Serialize(Stream Output, bool ToVersion)
        {
            using var BW = Output.GetWriter();
            if (!ToVersion)
            {
                BW.Write(Tools.ToUnixTime(Timestamp));
                BW.Write(Stream);
            }
            BW.Write((ulong)Services);
            if (Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                BW.Write(Address.GetAddressBytes());
            }
            else
            {
                BW.Write(Address.MapToIPv6().GetAddressBytes());
            }
            BW.Write(Port);
        }
    }
}