using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace Bitmessage.Global.Objects
{
    public class Message
    {
        public ulong AddressVersion { get; set; }

        public ulong StreamNumber { get; set; }

        public Behavior BehaviorBitfield { get; set; }

        public byte[] PubkeySign { get; set; }

        public byte[] PubkeyEnc { get; set; }

        public ulong NonceTrialsPerByte { get; set; }

        public ulong ExtraBytes { get; set; }

        public byte[] DestinationRipe { get; set; }

        public EncodingType Encoding { get; set; }

        public string Content { get; set; }

        public byte[] Ackdata { get; set; }

        public byte[] Signature { get; set; }


        public Message()
        {

        }

        public Message(byte[] Data)
        {
            using var MS = new MemoryStream(Data, false);
            using var BR = MS.GetReader();
            AddressVersion = BR.ReadVarInt();
            StreamNumber = BR.ReadVarInt();
            BehaviorBitfield = (Behavior)BR.ReadUInt32();
            PubkeySign = BR.ReadBytes(64);
            PubkeyEnc = BR.ReadBytes(64);
            if (AddressVersion >= 3)
            {
                NonceTrialsPerByte = BR.ReadVarInt();
                ExtraBytes = BR.ReadVarInt();
            }
            DestinationRipe = BR.ReadBytes(20);
            Encoding = (EncodingType)BR.ReadVarInt();
            Content = System.Text.Encoding.UTF8.GetString(BR.ReadBytes((int)BR.ReadVarInt()));
            Ackdata = BR.ReadBytes((int)BR.ReadVarInt());
            Signature = BR.ReadBytes((int)BR.ReadVarInt());
            if (MS.Position != MS.Length)
            {
                Debug.Print("Message: After decoding we're {0} bytes short.", MS.Length - MS.Position);
            }
        }
    }
}
