using Bitmessage.Global;
using DevHawk.Security.Cryptography;
using Secp256k1Net;
using System;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace Bitmessage.Cryptography
{
    public static class AddressGenerator
    {
        public const ulong DEFAULT_VERSION = 4;
        public const ulong DEFAULT_STREAM = 1;

        public static AddressInfo GenerateRandomAddress(bool shortAddress, ulong stream = DEFAULT_STREAM, ulong version = DEFAULT_VERSION)
        {
            var Addr = CreateAddress(shortAddress);
            Addr.ComputeEncodedAddress(version, stream);
            return Addr;
        }

        public static AddressInfo GenerateDeterministicAddress(string baseKey, bool shortAddress, ulong stream = DEFAULT_STREAM, ulong version = DEFAULT_VERSION)
        {
            return GenerateDeterministicAddress(Encoding.UTF8.GetBytes(baseKey), shortAddress, stream, version);
        }

        public static AddressInfo GenerateDeterministicAddress(byte[] baseKey, bool shortAddress, ulong stream = DEFAULT_STREAM, ulong version = DEFAULT_VERSION)
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
            using var generator = new Secp256k1();
            using var ripe = new RIPEMD160();

            //Combined key structure. Signing key first, then encryption key.
            //This avoids an unnecessary concatenation for hashing.
            byte[] combinedKey = new byte[Secp256k1.PUBKEY_LENGTH * 2];
            var pubSign = new Span<byte>(combinedKey, 0, Secp256k1.PUBKEY_LENGTH);
            var pubEnc = new Span<byte>(combinedKey, Secp256k1.PUBKEY_LENGTH, Secp256k1.PUBKEY_LENGTH);
            //Same as previous, but for serialized key data
            var serializedKeys = new byte[Secp256k1.SERIALIZED_UNCOMPRESSED_PUBKEY_LENGTH * 2];
            var serializedSign = new Span<byte>(serializedKeys, 0, Secp256k1.SERIALIZED_UNCOMPRESSED_PUBKEY_LENGTH);
            var serializedEnc = new Span<byte>(serializedKeys, Secp256k1.SERIALIZED_UNCOMPRESSED_PUBKEY_LENGTH, Secp256k1.SERIALIZED_UNCOMPRESSED_PUBKEY_LENGTH);

            AddressInfo AI = null;
            do
            {
                var privSign = new Span<byte>(Tools.Sha512(baseKey.Concat(VarInt.EncodeVarInt(sigKeyNonce)).ToArray()), 0, 32);
                var privEnc = new Span<byte>(Tools.Sha512(baseKey.Concat(VarInt.EncodeVarInt(encKeyNonce)).ToArray()), 0, 32);

                var ok =
                    generator.PublicKeyCreate(pubEnc, privEnc) &&
                    generator.PublicKeyCreate(pubSign, privSign) &&
                    generator.PublicKeySerialize(serializedSign, pubSign) &&
                    generator.PublicKeySerialize(serializedEnc, pubEnc);
                if (ok)
                {
                    var ripeHash = ripe.ComputeHash(Tools.Sha512(serializedKeys));
                    if (ripeHash.TakeWhile(m => m == 0).Count() == nullByteCount)
                    {
                        AI = new AddressInfo(privEnc.ToArray(), privSign.ToArray());
                    }
                }
                sigKeyNonce += 2;
                encKeyNonce += 2;
            } while (AI == null);
            Debug.Print("Key generator completed after {0} iterations", sigKeyNonce / 2);
            return AI;
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
