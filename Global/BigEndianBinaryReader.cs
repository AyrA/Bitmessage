using System;
using System.IO;
using System.Linq;
using System.Text;

namespace Bitmessage.Global
{
    public class BigEndianBinaryReader : IDisposable
    {
        private readonly BinaryReader reader;
        private bool disposed;

        public BigEndianBinaryReader(Stream Source, Encoding BaseEncoding, bool LeaveOpen)
        {
            if (Source is null)
            {
                throw new ArgumentNullException(nameof(Source));
            }

            if (BaseEncoding is null)
            {
                throw new ArgumentNullException(nameof(BaseEncoding));
            }
            disposed = false;
            reader = new BinaryReader(Source, BaseEncoding, LeaveOpen);
        }

        public byte[] ReadBytes(int Count)
        {
            var data = reader.ReadBytes(Count);
            if (data.Length < Count)
            {
                throw new IOException($"Requested to read {Count} bytes but {data.Length} were returned.");
            }
            return data;
        }

        public bool ReadBool()
        {
            return reader.ReadByte() != 0;
        }

        public ushort ReadUInt16()
        {
            var data = ReadBytes(2);
            if (BitConverter.IsLittleEndian)
            {
                return BitConverter.ToUInt16(data.Reverse().ToArray(), 0);
            }
            return BitConverter.ToUInt16(data);
        }

        public uint ReadUInt32()
        {
            var data = ReadBytes(4);
            if (BitConverter.IsLittleEndian)
            {
                return BitConverter.ToUInt32(data.Reverse().ToArray(), 0);
            }
            return BitConverter.ToUInt32(data);
        }

        public ulong ReadUInt64()
        {
            var data = ReadBytes(8);
            if (BitConverter.IsLittleEndian)
            {
                return BitConverter.ToUInt64(data.Reverse().ToArray(), 0);
            }
            return BitConverter.ToUInt64(data);
        }

        public ulong ReadVarInt()
        {
            return VarInt.DecodeVarInt(reader.BaseStream);
        }

        public string ReadVarIntString(int Limit = int.MaxValue)
        {
            var num = ReadVarInt();
            if (num == 0)
            {
                return string.Empty;
            }
            if (num > int.MaxValue)
            {
                throw new ArgumentOutOfRangeException($"Tried to decode VarIntString that is {num} bytes long but function limit is {int.MaxValue}");
            }
            if ((int)num > Limit)
            {
                throw new ArgumentOutOfRangeException($"Tried to decode VarIntString that is {num} bytes long but limit was set to {Limit}");
            }
            return Encoding.UTF8.GetString(reader.ReadBytes((int)num));
        }

        public void Dispose()
        {
            if (!disposed)
            {
                disposed = true;
                reader.Dispose();
            }
        }
    }
}
