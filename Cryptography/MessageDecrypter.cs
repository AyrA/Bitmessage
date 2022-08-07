using Bitmessage.Global;
using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;

namespace Bitmessage.Cryptography
{
    public static class MessageDecrypter
    {
        private const int AES_KEYSIZE = 32;
        private const int HMAC_SIZE = 32;

        private static readonly SHA1 Hasher = SHA1.Create();

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
            using var MS = new MemoryStream(Data, false);
            using var BR = MS.GetReader();
            var IV = BR.ReadBytes(16);
            var Curve = BR.ReadUInt16();
            var X = BR.ReadBytes(BR.ReadUInt16());
            var Y = BR.ReadBytes(BR.ReadUInt16());
            var MessageData = BR.ReadBytes((int)(MS.Length - MS.Position - HMAC_SIZE));
            var MAC = BR.ReadBytes(HMAC_SIZE);

            //Get full pubkey from compressed key
            //A compressed key is simply the X value prepended with 03 or 02.
            //- 0x02 --> Y is even
            //- 0x03 --> Y is odd
            var evenY = Y[^1] % 2 == 0;
            var CompressedPubkey = new byte[ECKey.PUBKEY_COMPRESSED_LENGTH];
            CompressedPubkey[0] = (byte)(evenY ? 0x02 : 0x03);
            //Copy X to compressed key. X may lack leading zeroes
            X.CopyTo(CompressedPubkey, CompressedPubkey.Length - X.Length);

            var WorkingPubkey = ECKey.FromPublic(CompressedPubkey);

            //Get final AES key by doing point multiplication

            var SharedKey = WorkingPubkey.Multiply(Key);

            try
            {
                return AES.Decrypt(MessageData, IV, SharedKey.GetEncoded(true)[1..]);
            }
            catch (Exception ex)
            {
                Debug.Print("Broadcast decrypt failed with error {0}", ex.Message);
            }
            return null;
        }
    }
}
