using System;
using System.Diagnostics;
using System.IO;

namespace Bitmessage.Global.Objects
{
    public class Message
    {
        public ulong MessageVersion { get; set; }

        public ulong AddressVersion { get; set; }

        public ulong StreamNumber { get; set; }

        public Behavior BehaviorBitfield { get; set; }

        public byte[] PubkeySign { get; set; }

        public byte[] PubkeyEnc { get; set; }

        public ulong NonceTrialsPerByte { get; set; }

        public ulong ExtraBytes { get; set; }

        public byte[] DestinationRipe { get; set; }

        public EncodingType Encoding { get; set; }

        public byte[] Content { get; set; }

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
            PubkeySign = BR.ReadBytes(Const.EC.PUBKEY_LENGTH);
            PubkeyEnc = BR.ReadBytes(Const.EC.PUBKEY_LENGTH);
            if (AddressVersion >= 3)
            {
                NonceTrialsPerByte = BR.ReadVarInt();
                ExtraBytes = BR.ReadVarInt();
            }
            DestinationRipe = BR.ReadBytes(Const.Crypto.RIPE_SIZE);
            Encoding = (EncodingType)BR.ReadVarInt();
            Content = BR.ReadBytes((int)BR.ReadVarInt());
            Ackdata = BR.ReadBytes((int)BR.ReadVarInt());
            Signature = BR.ReadBytes((int)BR.ReadVarInt());
            if (MS.Position != MS.Length)
            {
                Debug.Print("Message: After decoding we're {0} bytes short.", MS.Length - MS.Position);
            }
        }

        public void Serialize(Stream Output)
        {
            if (Output is null)
            {
                throw new ArgumentNullException(nameof(Output));
            }
            SerializeForSignature(Output);
            using var BW = Output.GetWriter();
            BW.WriteVarInt(Signature.Length);
            BW.Write(Signature);
            BW.Flush();
        }

        public void SerializeForSignature(Stream Output)
        {
            if (Output is null)
            {
                throw new ArgumentNullException(nameof(Output));
            }
            using var BW = Output.GetWriter();
            BW.WriteVarInt(AddressVersion);
            BW.WriteVarInt(StreamNumber);
            BW.Write((uint)BehaviorBitfield);
            BW.Write(PubkeySign);
            BW.Write(PubkeyEnc);
            if (AddressVersion >= 3)
            {
                BW.WriteVarInt(NonceTrialsPerByte);
                BW.WriteVarInt(ExtraBytes);
            }
            BW.Write(DestinationRipe);
            BW.WriteVarInt((ulong)Encoding);
            BW.WriteVarInt(Content.Length);
            BW.Write(Content);
            BW.WriteVarInt(Ackdata.Length);
            BW.Write(Ackdata);
            BW.Flush();
        }
    }
}
