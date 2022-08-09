﻿using Bitmessage.Global;
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

            if (Curve != 714)
            {
                throw new CryptographicException($"Unknown curve: {Curve}");
            }

            //Get full pubkey from compressed key
            //A compressed key is simply the X value prepended with 03 or 02.
            //- 0x02 --> Y is even
            //- 0x03 --> Y is odd
            var evenY = Y[^1] % 2 == 0;
            var CompressedPubkey = new byte[ECKey.PUBKEY_COMPRESSED_LENGTH];
            CompressedPubkey[0] = (byte)(evenY ? 0x02 : 0x03);
            //Copy X to compressed key. X may lack leading zeroes
            X.CopyTo(CompressedPubkey, CompressedPubkey.Length - X.Length);

            var PubkeyFromData = ECKey.FromPublic(CompressedPubkey);

#if DEBUG
            //Sanity check. Y from compressed X must equal Y from message data.
            if (!NativeMethods.CompareBytes(PubkeyFromData.GetRawPublic()[(64 - Y.Length)..], Y))
            {
                throw new CryptographicException("Validation of Y failed");
            }
#endif
            //Get AES key and MAC salt by doing ECDH and hashing the key
            var Keys = Hashing.Sha512(PubkeyFromData.Ecdh(Key));
            var AesKey = Keys[..AES_KEYSIZE];
            var HmacKey = Keys[AES_KEYSIZE..];

            //Validate HMAC before continuing

            //New HMAC: All data (except HMAC itself)
            if (!Hashing.ValidateMac(MAC, HmacKey, Data[..^HMAC_SIZE]))
            {
                Debug.Print("HMAC validation failed (Data block)");
                //Old HMAC: Ciphertext only
                if (!Hashing.ValidateMac(MAC, HmacKey, MessageData))
                {
                    Debug.Print("HMAC validation failed (MessageData)");
                    return null;
                }
            }

            try
            {
                return AES.Decrypt(MessageData, IV, AesKey);
            }
            catch (Exception ex)
            {
                Debug.Print("Broadcast decrypt failed with error {0}", ex.Message);
            }
            return null;
        }
    }
}
