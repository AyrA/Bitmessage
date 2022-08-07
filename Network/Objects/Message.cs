using Bitmessage.Cryptography;
using Bitmessage.Global;
using System;
using System.IO;
using System.Linq;
using System.Text;

namespace Bitmessage.Network.Objects
{
    public class Message : INetworkSerializable
    {
        public const int MAX_TYPE_NAME_LENGTH = 12;
        public const int MAX_PAYLOAD_SIZE = 1_600_003;

        public static readonly byte[] MagicBytes = new byte[] { 0xE9, 0xBE, 0xB4, 0xD9 };

        public byte[] Magic { get; set; } = (byte[])MagicBytes.Clone();

        public string MessageType { get; set; }

        public int PayloadLength { get => Payload == null ? 0 : Payload.Length; }

        public byte[] Payload { get; set; }

        public byte[] Checksum { get; set; }

        public Message()
        {
            Payload = new byte[0];
            CalculateChecksum();
        }

        public Message(string ObjectType)
        {
            if (ObjectType is null)
            {
                throw new ArgumentNullException(nameof(ObjectType));
            }

            if (Encoding.UTF8.GetByteCount(ObjectType) > MAX_TYPE_NAME_LENGTH)
            {
                throw new ArgumentOutOfRangeException(nameof(ObjectType), "Length can be at most {MAX_TYPE_NAME_LENGTH}");
            }
            MessageType = ObjectType;
            if(Payload is null)
            {
                Payload = new byte[0];
                CalculateChecksum();
            }
        }

        public Message(string ObjectType, INetworkSerializable PayloadData) : this(ObjectType)
        {
            if (PayloadData is null)
            {
                Payload = new byte[0];
            }
            else
            {
                using var MS = new MemoryStream();
                PayloadData.Serialize(MS);
                if (MS.Length > MAX_PAYLOAD_SIZE)
                {
                    throw new ArgumentException($"Object too large. Is {MS.Length} but can be at most {MAX_PAYLOAD_SIZE}", nameof(PayloadData));
                }
                Payload = MS.ToArray();
            }
            CalculateChecksum();
        }

        public Message(string ObjectType, byte[] SerializedPayloadData) : this(ObjectType)
        {
            if (SerializedPayloadData is null)
            {
                Payload = new byte[0];
            }
            else if (SerializedPayloadData.Length > MAX_PAYLOAD_SIZE)
            {
                throw new ArgumentException($"Object too large. Is {SerializedPayloadData.Length} but can be at most {MAX_PAYLOAD_SIZE}", nameof(SerializedPayloadData));
            }
            else
            {
                Payload = (byte[])SerializedPayloadData.Clone();
            }
            CalculateChecksum();
        }

        public bool VerifyChecksum()
        {
            return Checksum.SequenceEqual(Hashing.Sha512(Payload).Take(4));
        }

        public void CalculateChecksum()
        {
            Checksum = Hashing.Sha512(Payload).Take(4).ToArray();
        }

        public byte[] GetInvHash()
        {
            return Hashing.DoubleSha512(Payload).Take(32).ToArray();
        }

        public void Deserialize(Stream Input)
        {
            using var BR = Input.GetReader();
            Magic = BR.ReadBytes(4);
            MessageType = Encoding.UTF8.GetString(BR.ReadBytes(12)).TrimEnd('\0');
            var PayloadLength = BR.ReadUInt32();
            if (PayloadLength > MAX_PAYLOAD_SIZE)
            {
                throw new IOException($"Payload size is {PayloadLength} but can be at most {MAX_PAYLOAD_SIZE}");
            }
            Checksum = BR.ReadBytes(4);
            Payload = BR.ReadBytes((int)PayloadLength);
        }

        public void Serialize(Stream Output)
        {
            if (Payload is null)
            {
                throw new InvalidOperationException("Payload cannot be null");
            }
            var MessageBytes = Encoding.UTF8.GetBytes(MessageType);
            if (MessageBytes.Length > MAX_TYPE_NAME_LENGTH)
            {
                throw new InvalidOperationException("Message type name is too long");
            }
            if (Payload.Length > MAX_PAYLOAD_SIZE)
            {
                throw new InvalidOperationException("Payload too large");
            }
            if (Checksum is null)
            {
                CalculateChecksum();
            }
            //Extend to 12 bytes
            MessageBytes = Enumerable.Range(0, 12)
                .Select(m => MessageBytes.Length > m ? MessageBytes[m] : (byte)0)
                .ToArray();
            using var BW = Output.GetWriter();
            BW.Write(Magic);
            BW.Write(MessageBytes);
            BW.Write((uint)PayloadLength);
            BW.Write(Checksum);
            BW.Write(Payload);
        }

        public T DeserializePayload<T>() where T : INetworkSerializable
        {
            //Message objects require special handling
            if (typeof(T) == typeof(MessageObject))
            {
                return (T)(object)MessageObject.FromData(Payload);
            }

            var Constructor = typeof(T).GetConstructor(Type.EmptyTypes);
            if (Constructor == null)
            {
                throw new ArgumentException($"Type {typeof(T)} lacks a parameterless constructor");
            }
            var Instance = (T)Constructor.Invoke(null);
            using (var MS = new MemoryStream(Payload, false))
            {
                Instance.Deserialize(MS);
            }
            return Instance;
        }
    }
}
