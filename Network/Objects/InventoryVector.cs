using Bitmessage.Global;
using System.IO;

namespace Bitmessage.Network.Objects
{
    public class InventoryVector : INetworkSerializable
    {
        public const int MAX_ITEM_COUNT = 50_000;

        public InventoryItem[] Items { get; set; }

        public void Deserialize(Stream Input)
        {
            var Count = VarInt.DecodeVarInt(Input);
            if (Count > MAX_ITEM_COUNT)
            {
                throw new IOException("Too many items in inventory vector");
            }
            Items = new InventoryItem[(int)Count];
            for(var i = 0; i < Items.Length; i++)
            {
                Items[i] = new InventoryItem();
                Items[i].Deserialize(Input);
            }
        }

        public void Serialize(Stream Output)
        {
            VarInt.EncodeVarInt((ulong)Items.Length, Output);
            foreach(var Item in Items)
            {
                Item.Serialize(Output);
            }
        }
    }
}
