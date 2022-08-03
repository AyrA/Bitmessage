using Bitmessage.Global;
using System;
using System.IO;

namespace Bitmessage.Network.Objects
{
    public class InventoryItem : INetworkSerializable
    {
        public const int HASH_SIZE = 32;

        public byte[] Hash { get; set; }

        public void Deserialize(Stream Input)
        {
            using var BR = Input.GetReader();
            Hash = BR.ReadBytes(HASH_SIZE);
        }

        public void Serialize(Stream Output)
        {
            if (Hash == null || Hash.Length != HASH_SIZE)
            {
                throw new InvalidOperationException("Hash must be {HASH_SIZE} before serializing");
            }
            Output.Write(Hash, 0, Hash.Length);
        }
    }
}
