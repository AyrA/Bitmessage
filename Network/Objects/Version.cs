using Bitmessage.Global;
using System;
using System.IO;
using System.Linq;

namespace Bitmessage.Network.Objects
{
    public class Version : INetworkSerializable
    {
        public const int UA_SIZE_LIMIT = 5_000;
        public const int STREAM_NUM_LIMIT = 160_000;

        public VersionProtocol ProtocolVersion { get; set; }
        public VersionServices Services { get; set; }

        public DateTime Timestamp { get; set; }

        public NetworkAddress ReceiveAddress { get; set; }

        public NetworkAddress SendAddress { get; set; }

        public ulong Nonce { get; set; }

        public string UserAgent { get; set; }
        public ulong[] Streams { get; set; }


        public void GenerateNonce()
        {
            Nonce = BitConverter.ToUInt64(Tools.GetSafeRandomBytes(8), 0);
        }

        public void Deserialize(Stream Input)
        {
            using var BR = Input.GetReader();
            ProtocolVersion = (VersionProtocol)BR.ReadUInt32();
            Services = (VersionServices)BR.ReadUInt64();
            Timestamp = Tools.FromUnixTime(BR.ReadUInt64());
            ReceiveAddress = new NetworkAddress();
            SendAddress = new NetworkAddress();
            ReceiveAddress.Deserialize(Input, true);
            SendAddress.Deserialize(Input, true);
            Nonce = BR.ReadUInt64();
            UserAgent = BR.ReadVarIntString(UA_SIZE_LIMIT);
            var StreamCount = BR.ReadVarInt();
            if (StreamCount > STREAM_NUM_LIMIT)
            {
                throw new InvalidDataException("Too many streams in list");
            }
            Streams = Enumerable.Range(0, (int)StreamCount).Select(m => BR.ReadVarInt()).ToArray();
        }

        public void Serialize(Stream Output)
        {
            using var BW = Output.GetWriter();
            BW.Write((uint)ProtocolVersion);
            BW.Write((ulong)Services);
            BW.Write(Tools.ToUnixTime(Timestamp));
            using (var MS = new MemoryStream())
            {
                ReceiveAddress.Serialize(MS, true);
                SendAddress.Serialize(MS, true);
                BW.Write(MS.ToArray());
            }
            BW.Write(Nonce);
            BW.Write(UserAgent);
            BW.Write(VarInt.EncodeVarInt((ulong)Streams.Length));
            foreach(var Entry in Streams)
            {
                BW.Write(VarInt.EncodeVarInt(Entry));
            }
        }
    }

    public enum VersionProtocol : int
    {
        /// <summary>
        /// Deprecated
        /// </summary>
        Version2 = 2,
        /// <summary>
        /// Current version
        /// </summary>
        Version3 = 3
    }

    [Flags]
    public enum VersionServices : ulong
    {
        /// <summary>
        /// Generic network node
        /// </summary>
        NetworkNode = 1,
        /// <summary>
        /// TLS support
        /// </summary>
        Ssl = NetworkNode << 1,
        /// <summary>
        /// POW offloading
        /// </summary>
        Pow = Ssl << 1,
        /// <summary>
        /// Dandelion protocol
        /// </summary>
        Dandelion = Pow << 1
    }
}
