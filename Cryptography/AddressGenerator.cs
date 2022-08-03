using Bitmessage.Global;
using DevHawk.Security.Cryptography;
using Secp256k1Net;
using System;
using System.Diagnostics;
using System.Linq;

namespace Bitmessage.Cryptography
{
    public static class AddressGenerator
    {
        public const ulong DEFAULT_VERSION = 4;
        public const ulong DEFAULT_STREAM = 1;

        public static AddressInfo GenerateAddress(bool shortAddress, ulong stream = DEFAULT_STREAM, ulong version = DEFAULT_VERSION)
        {
            var Addr = CreateAddress(shortAddress);
            Addr.ComputeEncodedAddress(version, stream);
            return Addr;
        }

        private static AddressInfo CreateAddress(bool shortAddress)
        {
            using var Hasher = new RIPEMD160();
            using var ECDH = new Secp256k1();
            var Info = new AddressInfo();
            var StartSequence = new byte[shortAddress ? 2 : 1];

            Debug.Print("Generating encryption key with {0} leading nullbytes...", StartSequence.Length);
            while (!Hasher.ComputeHash(Tools.Sha512(Info.PublicSigningKey.Concat(Info.PublicEncryptionKey).ToArray())).Take(StartSequence.Length).SequenceEqual(StartSequence))
            {
                Info.CreateEncryptionKey(ECDH);
            }
            /* NOTE: The hash limitation only applies to the encryption key
            Debug.Print("Generating signing key...");
            while (!Hasher.ComputeHash(Tools.Sha512(Info.PublicSigningKey)).Take(StartSequence.Length).SequenceEqual(StartSequence))
            {
                Info.CreateSigningKey(ECDH);
            }
            //*/
            Debug.Print("Keys generated");

            return Info;
        }
    }
}
