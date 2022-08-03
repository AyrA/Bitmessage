using System;
using System.IO;

namespace Bitmessage.Global
{
    public static class VarInt
    {
        public static int GetVarIntSize(ulong Num)
        {
            if (Num < 0xFD)
            {
                return 1;
            }
            if (Num <= 0xFFFF)
            {
                return 3;
            }
            if (Num <= 0xFFFFFFFF)
            {
                return 5;
            }
            return 9;
        }

        public static ulong DecodeVarInt(byte[] Data, int Offset = 0)
        {
            if (Data is null)
            {
                throw new ArgumentNullException(nameof(Data));
            }

            switch (Data[Offset + 0])
            {
                case 0xFF:
                    if (!BitConverter.IsLittleEndian)
                    {
                        return BitConverter.ToUInt64(Data, Offset + 1);
                    }
                    return
                        (ulong)Data[Offset + 1] << 56 |
                        (ulong)Data[Offset + 2] << 48 |
                        (ulong)Data[Offset + 3] << 40 |
                        (ulong)Data[Offset + 4] << 32 |
                        (ulong)Data[Offset + 5] << 24 |
                        (ulong)Data[Offset + 6] << 16 |
                        (ulong)Data[Offset + 7] << 8 |
                        Data[Offset + 8];
                case 0xFE:
                    if (!BitConverter.IsLittleEndian)
                    {
                        return BitConverter.ToUInt32(Data, Offset + 1);
                    }
                    return
                        (ulong)Data[Offset + 1] << 24 |
                        (ulong)Data[Offset + 2] << 16 |
                        (ulong)Data[Offset + 3] << 8 |
                        Data[Offset + 4];
                case 0xFD:
                    if (!BitConverter.IsLittleEndian)
                    {
                        return BitConverter.ToUInt16(Data, Offset + 1);
                    }
                    return (ulong)(
                        Data[Offset + 1] << 8 |
                        Data[Offset + 2]
                        );
                default:
                    return Data[0];
            }
        }

        public static ulong DecodeVarInt(Stream Source)
        {
            if (Source is null)
            {
                throw new ArgumentNullException(nameof(Source));
            }

            var b = new byte[9];
            if (Source.Read(b, 0, 1) > 0)
            {
                switch (b[0])
                {
                    case 0xFF:
                        Source.Read(b, 1, 8);
                        break;
                    case 0xFE:
                        Source.Read(b, 1, 4);
                        break;
                    case 0xFD:
                        Source.Read(b, 1, 2);
                        break;
                    default:
                        return b[0];
                }
                return DecodeVarInt(b, 0);
            }
            throw new IOException("End of stream");
        }

        public static byte[] EncodeVarInt(ulong Num)
        {

            if (Num < 0xFD)
            {
                return new byte[]
                {
                    (byte)Num
                };
            }
            if (Num <= 0xFFFF)
            {
                return new byte[]
                {
                    0xFD,
                    (byte)((Num >> 8 ) & 0xFF),
                    (byte)(Num         & 0xFF)
                };
            }
            if (Num <= 0xFFFFFFFF)
            {
                return new byte[]
                {
                    0xFE,
                    (byte)((Num >> 24) & 0xFF),
                    (byte)((Num >> 16) & 0xFF),
                    (byte)((Num >> 8 ) & 0xFF),
                    (byte)(Num         & 0xFF)
                };
            }
            return new byte[]
            {
                    0xFF,
                    (byte)((Num >> 56) & 0xFF),
                    (byte)((Num >> 48) & 0xFF),
                    (byte)((Num >> 40) & 0xFF),
                    (byte)((Num >> 32) & 0xFF),
                    (byte)((Num >> 24) & 0xFF),
                    (byte)((Num >> 16) & 0xFF),
                    (byte)((Num >> 8 ) & 0xFF),
                    (byte)(Num         & 0xFF)
            };
        }

        public static byte[] EncodeVarInt(ulong Num, Stream Output)
        {
            if (Output is null)
            {
                throw new ArgumentNullException(nameof(Output));
            }

            var Data = EncodeVarInt(Num);
            Output.Write(Data, 0, Data.Length);
            return Data;
        }
    }
}
