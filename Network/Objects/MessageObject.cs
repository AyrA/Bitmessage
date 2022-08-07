using Bitmessage.Cryptography;
using Bitmessage.Global;
using System;
using System.IO;
using System.Linq;

namespace Bitmessage.Network.Objects
{
    public class MessageObject : INetworkSerializable
    {
        /// <summary>
        /// Math.Pow(2,18)
        /// </summary>
        public const int MAX_OBJECT_SIZE = 262144;

        public ulong Nonce { get; set; }

        public DateTime Expiration { get; set; }

        public MessageObjectType ObjectType { get; set; }

        public ulong Version { get; set; }

        public ulong StreamNumber { get; set; }

        public byte[] Payload { get; set; }

        public bool VerifyPOW(uint PayloadLengthExtraBytes = POW.DEFAULT_DIFFICULTY, uint NonceTrialsPerByte = POW.DEFAULT_DIFFICULTY)
        {
            using var MS = new MemoryStream();
            Serialize(MS);
            return POW.CheckPOW(MS.ToArray(), PayloadLengthExtraBytes, NonceTrialsPerByte);
        }

        public ulong GetTargetDifficulty(uint PayloadLengthExtraBytes = POW.DEFAULT_DIFFICULTY, uint NonceTrialsPerByte = POW.DEFAULT_DIFFICULTY)
        {
            using var MS = new MemoryStream();
            Serialize(MS);
            return (ulong)POW.GetTargetPOWValue(MS.ToArray(), PayloadLengthExtraBytes, NonceTrialsPerByte);
        }

        public ulong GetDifficulty()
        {
            using var MS = new MemoryStream();
            Serialize(MS);
            return POW.GetPOWValue(MS.ToArray());
        }

        public void ComputePOW(uint PayloadLengthExtraBytes = POW.DEFAULT_DIFFICULTY, uint NonceTrialsPerByte = POW.DEFAULT_DIFFICULTY)
        {
            using var MS = new MemoryStream();
            Serialize(MS);
            //Data without nonce
            var BaseData = MS.ToArray().Skip(8).ToArray();
            //Add empty nonce for target calculation
            var CombinedData = new byte[8].Concat(BaseData).ToArray();
            var Target = Math.Floor(POW.GetTargetPOWValue(CombinedData, PayloadLengthExtraBytes, NonceTrialsPerByte));
            //Calculate real nonce below target
            Nonce = POW.DoPOW(Hashing.Sha512(BaseData), (ulong)Target);
        }

        public static MessageObject FromData(byte[] Data)
        {
            var MO = new MessageObject();
            using (var MS = new MemoryStream(Data, false))
            {
                MO.Deserialize(MS, Data.Length);
            }
            return MO;
        }

        public void Deserialize(Stream Input, int RemainingBytes)
        {
            if(RemainingBytes> MAX_OBJECT_SIZE)
            {
                throw new InvalidDataException($"Object too big. It's {RemainingBytes} bytes but can be at most {MAX_OBJECT_SIZE} bytes");
            }
            using var BR = Input.GetReader();
            Nonce = BR.ReadUInt64();
            Expiration = Tools.FromUnixTime(BR.ReadUInt64());
            ObjectType = (MessageObjectType)BR.ReadUInt32();
            //Messages do not have a version
            if (ObjectType != MessageObjectType.Message)
            {
                Version = BR.ReadVarInt();
                RemainingBytes -= VarInt.GetVarIntSize(Version);
            }
            StreamNumber = BR.ReadVarInt();
            //Change remaining byte counter in accordance with read values
            RemainingBytes -= sizeof(ulong) + sizeof(ulong) + sizeof(uint) + VarInt.GetVarIntSize(StreamNumber);
            switch (ObjectType)
            {
                case MessageObjectType.GetPubkey:
                    Payload = BR.ReadBytes(RemainingBytes);
                    break;
                case MessageObjectType.Pubkey:
                    if (Version < 3)
                    {
                        Payload = BR.ReadBytes(4 + 64 + 64);
                    }
                    else if (Version == 3)
                    {
                        var BaseData = BR.ReadBytes(4 + 64 + 64);
                        var Ints = new ulong[]
                        {
                            BR.ReadVarInt(), BR.ReadVarInt()
                        }.SelectMany(VarInt.EncodeVarInt).ToArray();
                        var sigSize = BR.ReadVarInt();
                        Payload = BaseData
                            .Concat(Ints)
                            .Concat(VarInt.EncodeVarInt(sigSize))
                            .Concat(BR.ReadBytes((int)sigSize))
                            .ToArray();
                    }
                    else if (Version == 4)
                    {
                        Payload = BR.ReadBytes(RemainingBytes);
                    }
                    else
                    {
                        throw new Exception($"Unsupported pubkey version {Version}");
                    }
                    RemainingBytes -= Payload.Length;
                    break;
                case MessageObjectType.Message:
                case MessageObjectType.Broadcast:
                default:
                    Payload = BR.ReadBytes(RemainingBytes);
                    break;
            }
            if (RemainingBytes != Payload.Length)
            {
                //TODO: Find a way to report this
                System.Diagnostics.Debug.Print($"Payload size of {Payload.Length} does not match expected size of {RemainingBytes}");
            }
        }

        public void Deserialize(Stream Input)
        {
            throw new InvalidOperationException("This function will not work without the second argument");
        }

        public void Serialize(Stream Output)
        {
            using var BW = Output.GetWriter();
            BW.Write(Nonce);
            BW.Write(Tools.ToUnixTime(Expiration));
            BW.Write((uint)ObjectType);
            //Messages do not have a version
            if (ObjectType != MessageObjectType.Message)
            {
                BW.WriteVarInt(Version);
            }
            BW.WriteVarInt(StreamNumber);
            BW.Write(Payload);
        }
    }

    public enum MessageObjectType : uint
    {
        GetPubkey = 0,
        Pubkey = 1,
        Message = 2,
        Broadcast = 3
    }
}
