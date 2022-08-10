using System.Diagnostics;
using System.IO;

namespace Bitmessage.Global.Objects
{
    public class Broadcast
    {
        public ulong AddressVersion { get; set; }
        
        public ulong StreamNumber { get; set; }

        public Behavior BehaviorBitfield { get; set; }

        public byte[] PubkeySign { get; set; }
        
        public byte[] PubkeyEnc { get; set; }

        public ulong NonceTrialsPerByte { get; set; }
        
        public ulong ExtraBytes { get; set; }
        
        public EncodingType Encoding { get; set; }

        public string Content { get; set; }

        public byte[] Signature { get; set; }

        public Broadcast()
        {

        }

        public Broadcast(byte[] Data)
        {
            using var MS = new MemoryStream(Data, false);
            using var BR = MS.GetReader();
            AddressVersion = BR.ReadVarInt();
            StreamNumber = BR.ReadVarInt();
            BehaviorBitfield = (Behavior)BR.ReadUInt32();
            PubkeySign = BR.ReadBytes(Const.EC.PUBKEY_LENGTH);
            PubkeyEnc = BR.ReadBytes(Const.EC.PUBKEY_LENGTH);
            if (AddressVersion >= 3)
            {
                NonceTrialsPerByte = BR.ReadVarInt();
                ExtraBytes = BR.ReadVarInt();
            }
            Encoding = (EncodingType)BR.ReadVarInt();
            Content = System.Text.Encoding.UTF8.GetString(BR.ReadBytes((int)BR.ReadVarInt()));
            Signature = BR.ReadBytes((int)BR.ReadVarInt());
            if (MS.Position != MS.Length)
            {
                Debug.Print("Broadcast: After decoding we're {0} bytes short.", MS.Length - MS.Position);
            }
        }
    }
}
