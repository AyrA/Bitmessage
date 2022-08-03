using Bitmessage.Global;
using System;
using System.IO;

namespace Bitmessage.Network.Objects
{
    public class AddressList : INetworkSerializable
    {
        public const int MAX_ADDR_COUNT = 1000;

        public NetworkAddress[] Addresses { get; set; }

        public void Deserialize(Stream Input)
        {
            var Count = VarInt.DecodeVarInt(Input);
            if (Count > MAX_ADDR_COUNT)
            {
                throw new IOException($"Tried to decode {Count} addresses but maximum allowed is {MAX_ADDR_COUNT}");
            }
            Addresses = new NetworkAddress[(int)Count];
            for (var i = 0; i < Addresses.Length; i++)
            {
                Addresses[i] = new NetworkAddress();
                Addresses[i].Deserialize(Input);
            }
        }

        public void Serialize(Stream Output)
        {
            if (Addresses == null)
            {
                throw new InvalidOperationException("Address list is null");
            }
            if (Addresses.Length > MAX_ADDR_COUNT)
            {
                throw new InvalidOperationException($"Maximum address list size is {MAX_ADDR_COUNT}");
            }
            VarInt.EncodeVarInt((ulong)Addresses.Length, Output);
            foreach(var Addr in Addresses)
            {
                Addr.Serialize(Output);
            }
        }
    }
}
