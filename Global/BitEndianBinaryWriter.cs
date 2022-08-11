using System;
using System.IO;
using System.Linq;
using System.Text;

namespace Bitmessage.Global
{
    public class BitEndianBinaryWriter : IDisposable
    {
        private readonly BinaryWriter writer;
        private bool disposed;

        public BitEndianBinaryWriter(Stream Source, Encoding BaseEncoding, bool LeaveOpen)
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
            writer = new BinaryWriter(Source, BaseEncoding, LeaveOpen);
        }

        public void WriteVarInt(ulong value)
        {
            Write(VarInt.EncodeVarInt(value));
        }

        public void WriteVarInt(uint value)
        {
            Write(VarInt.EncodeVarInt(value));
        }

        public void WriteVarInt(long value)
        {
            Write(VarInt.EncodeVarInt((ulong)value));
        }

        public void WriteVarInt(int value)
        {
            Write(VarInt.EncodeVarInt((uint)value));
        }

        public void Write(bool data)
        {
            Write(data ? new byte[] { 1 } : new byte[] { 0 });
        }

        public void Write(string VarIntString)
        {
            if (string.IsNullOrEmpty(VarIntString))
            {
                writer.Write((byte)0);
            }
            else
            {
                var str = Encoding.UTF8.GetBytes(VarIntString);
                Write(VarInt.EncodeVarInt((ulong)str.Length));
                Write(str);
            }
        }

        public void Write(ulong data)
        {
            var bytes = BitConverter.GetBytes(data);
            Write(BitConverter.IsLittleEndian ? bytes.Reverse().ToArray() : bytes);
        }

        public void Write(uint data)
        {
            var bytes = BitConverter.GetBytes(data);
            Write(BitConverter.IsLittleEndian ? bytes.Reverse().ToArray() : bytes);
        }

        public void Write(ushort data)
        {
            var bytes = BitConverter.GetBytes(data);
            Write(BitConverter.IsLittleEndian ? bytes.Reverse().ToArray() : bytes);
        }

        public void Write(byte[] bytes)
        {
            writer.Write(bytes);
        }

        public void Flush()
        {
            writer.Flush();
        }

        public void Dispose()
        {
            if (!disposed)
            {
                disposed = true;
                Flush();
                writer.Dispose();
            }
        }
    }
}
