using Bitmessage.Global;
using System;
using System.Linq;

namespace Bitmessage.Cryptography
{

    public static class POW
    {
        public const uint DEFAULT_DIFFICULTY = 1000;

        public static double GetTargetPOWValue(byte[] Data, uint PayloadLengthExtraBytes = DEFAULT_DIFFICULTY, uint NonceTrialsPerByte = DEFAULT_DIFFICULTY)
        {
            var PayloadToCheck = Data.Skip(8).ToArray();
            var Expiration = Tools.FromUnixTime(Tools.ToUInt64(PayloadToCheck.Take(8).ToArray()));
            var TTL = Math.Max(300, (int)Expiration.Subtract(DateTime.UtcNow).TotalSeconds);
            return ulong.MaxValue / (NonceTrialsPerByte * (PayloadToCheck.Length + 8 + PayloadLengthExtraBytes + ((TTL * (PayloadToCheck.Length + 8 + PayloadLengthExtraBytes)) / Math.Pow(2, 16))));
        }

        public static bool CheckPOW(byte[] Data, uint PayloadLengthExtraBytes = DEFAULT_DIFFICULTY, uint NonceTrialsPerByte = DEFAULT_DIFFICULTY)
        {
            var TargetValue = GetTargetPOWValue(Data, PayloadLengthExtraBytes, NonceTrialsPerByte);
            return GetPOWValue(Data) <= TargetValue;
        }

        public static ulong GetPOWValue(byte[] Data)
        {
            var Nonce = Data.Take(8).ToArray();
            var PayloadToCheck = Data.Skip(8).ToArray();
            var Hash = Hashing.DoubleSha512(Nonce.Concat(Hashing.Sha512(PayloadToCheck)).ToArray());
            return Tools.ToUInt64(Hash);
        }

        public static ulong DoPOW(byte[] InitialHash, ulong TargetDifficulty)
        {
            if (InitialHash is null || InitialHash.Length != 64)
            {
                throw new ArgumentException("Hash for POW must be 64 bytes long");
            }
            return NativeMethods.DoPOW(InitialHash, TargetDifficulty);
        }
    }
}
