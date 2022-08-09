using System;
using System.Collections.Generic;
using System.Linq;

namespace Bitmessage.Global
{
    public static class Tools
    {
        public const string USER_AGENT = "Bitmessage.Network/0.1";

        private static readonly DateTime Epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        public static byte[] GetBytes(ulong Value)
        {
            if (BitConverter.IsLittleEndian)
            {
                BitConverter.GetBytes(Value).Reverse().ToArray();
            }
            return BitConverter.GetBytes(Value);
        }

        public static ulong ToUInt64(byte[] Data, int Offset = 0)
        {
            if (BitConverter.IsLittleEndian)
            {
                return BitConverter.ToUInt64(Data.Skip(Offset).Take(8).Reverse().ToArray(), 0);
            }
            return BitConverter.ToUInt64(Data, Offset);
        }

        public static uint ToUInt32(byte[] Data, int Offset = 0)
        {
            if (BitConverter.IsLittleEndian)
            {
                return BitConverter.ToUInt32(Data.Skip(Offset).Take(4).Reverse().ToArray(), 0);
            }
            return BitConverter.ToUInt32(Data, Offset);
        }

        /// <summary>
        /// Increments an arbitrary long unsigned number that's stored in big endian format
        /// </summary>
        /// <param name="Data"></param>
        /// <returns>true, if overflowed</returns>
        public static bool Inc(byte[] Data)
        {
            int i = Data.Length - 1;
            while (++Data[i] == 0 && --i < 0) ;
            return i < 0 && Data[0] == 0;
        }

        public static byte[] GetSafeRandomBytes(int Count)
        {
            var Ret = new byte[Count];
            using var RNG = System.Security.Cryptography.RandomNumberGenerator.Create();
            RNG.GetBytes(Ret);
            return Ret;
        }

        public static DateTime FromUnixTime(ulong UnixTime)
        {
            return Epoch.AddSeconds(UnixTime);
        }

        public static ulong ToUnixTime(DateTime DT)
        {
            return (ulong)DT.ToUniversalTime().Subtract(Epoch).TotalSeconds;
        }

        public static string Hexlify(IEnumerable<byte> data, string Separator = ":")
        {
            if (data is null)
            {
                return null;
            }
            return string.Join(Separator, data.Select(m => m.ToString("X2")));
        }
    }
}
