using System;
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

        public static void Inc(byte[] Data)
        {
            int i = Data.Length - 1;
            while (++Data[i] == 0 && --i > 0) ;
        }

        public static byte[] GetCryptoBytes(int Count)
        {
            var Ret = new byte[Count];
            using var RNG = System.Security.Cryptography.RandomNumberGenerator.Create();
            RNG.GetBytes(Ret);
            return Ret;
        }

        public static byte[] Sha512(byte[] Data)
        {
            if (Data is null)
            {
                throw new ArgumentNullException(nameof(Data));
            }

            using var Hasher = System.Security.Cryptography.SHA512.Create();
            return Hasher.ComputeHash(Data);
        }

        /// <summary>
        /// This is faster than calling <see cref="Sha512(byte[])"/> twice
        /// </summary>
        /// <param name="Data"></param>
        /// <returns></returns>
        public static byte[] DoubleSha512(byte[] Data)
        {
            if (Data is null)
            {
                throw new ArgumentNullException(nameof(Data));
            }
            using var Hasher = System.Security.Cryptography.SHA512.Create();
            return Hasher.ComputeHash(Hasher.ComputeHash(Data));
        }

        public static DateTime FromUnixTime(ulong UnixTime)
        {
            return Epoch.AddSeconds(UnixTime);
        }

        public static ulong ToUnixTime(DateTime DT)
        {
            return (ulong)DT.ToUniversalTime().Subtract(Epoch).TotalSeconds;
        }
    }
}
