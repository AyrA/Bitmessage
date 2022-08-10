using Bitmessage.Global;
using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;

namespace Bitmessage.Cryptography
{
    public static class ObjectDecrypter
    {
        /// <summary>
        /// Tries to decrypt a broadcast message with the given hash
        /// </summary>
        /// <param name="Data">Broadcast message</param>
        /// <param name="Key">
        /// Private EC key.
        /// For a broadcast, the leading 32 bytes obtained with
        /// <see cref="AddressInfo.GetBroadcastHash(string)"/>
        /// </param>
        /// <returns>Decrypted data on success, null on failure</returns>
        public static byte[] DecryptBroadcast(byte[] Data, ECKey Key)
        {
            if (Data is null)
            {
                throw new ArgumentNullException(nameof(Data));
            }

            if (Key is null)
            {
                throw new ArgumentNullException(nameof(Key));
            }

            var Payload = new ECIES(Data);

            if (Payload.CurveType != Const.EC.CURVE_IDENTIFIER)
            {
                throw new CryptographicException($"Unknown curve: {Payload.CurveType}");
            }

            return Payload.VerifyAndDecrypt(Hashing.Sha512(Payload.PublicKey.Ecdh(Key)));
        }

        /// <summary>
        /// Tries to decrypt a private message with the given key
        /// </summary>
        /// <param name="Data">Message</param>
        /// <param name="Address">Bitmessage address</param>
        /// <returns>Decrypted data on success, null on failure</returns>
        public static byte[] DecryptMessage(byte[] Data, AddressInfo Address)
        {
            return DecryptMessage(Data, Address, false);
        }

        /// <summary>
        /// Tries to decrypt a private message with the given key
        /// </summary>
        /// <param name="Data">Message</param>
        /// <param name="Address">Bitmessage address</param>
        /// <param name="HasVersion">Should be false unless you're sure the object has a version</param>
        /// <returns>Decrypted data on success, null on failure</returns>
        /// <remarks>
        /// If <paramref name="HasVersion"/> is false,
        /// decryption is attempted again with it set to "true" if it fails for the first time.
        /// </remarks>
        private static byte[] DecryptMessage(byte[] Data, AddressInfo Address, bool HasVersion)
        {
            if (Data is null)
            {
                throw new ArgumentNullException(nameof(Data));
            }
            if (Address is null)
            {
                throw new ArgumentNullException(nameof(Address));
            }
            if (Address.EncryptionKey.PrivateKey == null || Address.SigningKey.PrivateKey == null)
            {
                throw new ArgumentException("Address must contain private key");
            }
            ECIES Payload;
            if (HasVersion)
            {
                var Version = VarInt.DecodeVarInt(Data);
                if (Version != 1)
                {
                    Debug.Print("Version is not 1. Is {0}", Version);
                    return null;
                }
                Payload = new ECIES(Data[VarInt.GetVarIntSize(Version)..]);
            }
            else
            {
                try
                {
                    Payload = new ECIES(Data);
                }
                catch
                {
                    return DecryptMessage(Data, Address, true);
                }
            }
            return Payload.VerifyAndDecrypt(Hashing.Sha512(Payload.PublicKey.Ecdh(Address.EncryptionKey)));
        }
    }
}
