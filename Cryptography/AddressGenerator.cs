using Bitmessage.Global;
using System;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace Bitmessage.Cryptography
{
    public static class AddressGenerator
    {
        public static AddressInfo GenerateRandomAddress(bool shortAddress, ulong stream = Const.Addr.DEFAULT_STREAM, ulong version = Const.Addr.DEFAULT_VERSION)
        {
            var Addr = CreateAddress(shortAddress);
            Addr.ComputeEncodedAddress(version, stream);
            return Addr;
        }

        public static AddressInfo GenerateDeterministicAddress(string baseKey, bool shortAddress, ulong stream = Const.Addr.DEFAULT_STREAM, ulong version = Const.Addr.DEFAULT_VERSION)
        {
            return GenerateDeterministicAddress(Encoding.UTF8.GetBytes(baseKey), shortAddress, stream, version);
        }

        public static AddressInfo GenerateDeterministicAddress(byte[] baseKey, bool shortAddress, ulong stream = Const.Addr.DEFAULT_STREAM, ulong version = Const.Addr.DEFAULT_VERSION)
        {
            var Addr = CreateDeterministicAddress(baseKey, shortAddress);
            Addr.ComputeEncodedAddress(version, stream);
            return Addr;
        }

        private static AddressInfo CreateDeterministicAddress(byte[] baseKey, bool shortAddress)
        {
            var nullByteCount = shortAddress ? 2 : 1;
            ulong sigKeyNonce = 0;
            ulong encKeyNonce = 1;
            AddressInfo AI = null;
            //Reusing the same hashing component is better than doing Hashing.Sha512(...) repeatedly
            using var SHA512 = System.Security.Cryptography.SHA512.Create();
            do
            {
                var privSign = new ECKey(SHA512.ComputeHash(baseKey.Concat(VarInt.EncodeVarInt(sigKeyNonce)).ToArray())[..32]);
                var privEnc = new ECKey(SHA512.ComputeHash(baseKey.Concat(VarInt.EncodeVarInt(encKeyNonce)).ToArray())[..32]);

                var serializedKeys = privSign.SerializePublic(false).Concat(privEnc.SerializePublic(false)).ToArray();

                var ripeHash = Hashing.RIPEMD160(SHA512.ComputeHash(serializedKeys));
                if (ripeHash[..nullByteCount].All(m => m == 0))
                {
                    AI = new AddressInfo(privSign, privEnc);
                }
                sigKeyNonce += 2;
                encKeyNonce += 2;
            } while (AI == null);
            Debug.Print("Deterministic key generator completed after {0} iterations", sigKeyNonce / 2);
            return AI;
        }

        private static AddressInfo CreateAddress(bool shortAddress)
        {
            //To speed up the process we only re-generate one of the two keys.
            var Key1 = new ECKey();
            var Key2 = new ECKey();
            var Public2 = Key2.SerializePublic(false);
            var StartSequence = new byte[shortAddress ? 2 : 1];
            int iterartions = 0;
            Debug.Print("Generating encryption key with {0} leading nullbytes...", StartSequence.Length);
            while (!Hashing.RIPEMD160(Hashing.Sha512(Key1.SerializePublic(false).Concat(Public2).ToArray())).Take(StartSequence.Length).SequenceEqual(StartSequence))
            {
                Key1 = new ECKey();
                ++iterartions;
            }
            Debug.Print("Random key generator completed after {0} iterations", iterartions);

            return new AddressInfo(Key1, Key2);
        }
    }
}
