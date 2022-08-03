using Bitmessage.Global;
using System.IO;

namespace Bitmessage.Network.Objects
{
    public class ErrorMessage : INetworkSerializable
    {
        public ErrorType ErrorType { get; set; }
        public ulong BanTime { get; set; }
        public string InventoryVector { get; set; }
        public string ErrorText { get; set; }

        public void Deserialize(Stream Input)
        {
            ErrorType = (ErrorType)VarInt.DecodeVarInt(Input);
            BanTime = VarInt.DecodeVarInt(Input);
            using var BR = Input.GetReader();
            InventoryVector = BR.ReadVarIntString();
            ErrorText = BR.ReadVarIntString();
        }

        public void Serialize(Stream Output)
        {
            using var BW = Output.GetWriter();
            BW.WriteVarInt((ulong)ErrorType);
            BW.WriteVarInt(BanTime);
            BW.Write(InventoryVector);
            BW.Write(ErrorText);
        }
    }

    public enum ErrorType : ulong
    {
        Generic = 0,
        Warning = 1,
        FatalError = 2
    }
}
