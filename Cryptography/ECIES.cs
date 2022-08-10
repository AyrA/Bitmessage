using Bitmessage.Global;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Bitmessage.Cryptography
{
    public class ECIES
    {
        public byte[] IV { get; set; }

        public ushort CurveType { get; set; }

        public ECKey PublicKey { get; set; }

        public byte[] Payload { get; set; }

        public byte[] Hmac { get; set; }

        public ECIES()
        {

        }

        public ECIES(byte[] Data)
        {
            if (Data is null)
            {
                throw new ArgumentNullException(nameof(Data));
            }
            using var MS = new MemoryStream(Data, false);
            using var BR = MS.GetReader();
            IV = BR.ReadBytes(Const.Crypto.AES_BLOCKSIZE);
            CurveType = BR.ReadUInt16();
            var X = BR.ReadBytes(BR.ReadUInt16());
            var Y = BR.ReadBytes(BR.ReadUInt16());
            Payload = BR.ReadBytes((int)(MS.Length - MS.Position - Const.Crypto.HMAC_SIZE));
            Hmac = BR.ReadBytes(Const.Crypto.HMAC_SIZE);

            //Validate pubkey
            var CompressedKey = new byte[X.Length + 1];
            X.CopyTo(CompressedKey, 1);
            CompressedKey[0] = Y[^1] % 2 == 0 ? Const.EC.EVEN_Y : Const.EC.ODD_Y;
            PublicKey = ECKey.FromPublic(CompressedKey);
#if DEBUG
            //Sanity check. Y from compressed X must equal Y from message data.
            if (!NativeMethods.CompareBytes(PublicKey.GetRawPublic()[(Const.EC.PUBKEY_LENGTH - Y.Length)..], Y))
            {
                throw new CryptographicException("Validation of Y failed");
            }
#endif
        }

        public bool CheckHmac(byte[] Key)
        {
            if (Key is null)
            {
                throw new ArgumentNullException(nameof(Key));
            }
            //HMAC variant A: Ciphertext only
            if (Hashing.ValidateMac(Hmac, Key, Payload))
            {
                return true;
            }
            Debug.Print("HMAC validation failed (MessageData)");

            //HMAC variant B: All data (except HMAC itself)
            var Data = Serialize()[..^Const.Crypto.HMAC_SIZE];
            if (Hashing.ValidateMac(Hmac, Key, Data))
            {
                return true;
            }
            Debug.Print("HMAC validation failed (Data block)");
            return false;
        }

        public byte[] Decrypt(byte[] Key)
        {
            if (Key is null)
            {
                throw new ArgumentNullException(nameof(Key));
            }
            try
            {
                return AES.Decrypt(Payload, IV, Key);
            }
            catch (Exception ex)
            {
                Debug.Print("ECIES decryption failed with error [{0}]: {1}", ex.GetType(), ex.Message);
            }
            return null;
        }

        public byte[] VerifyAndDecrypt(byte[] CombinedKey)
        {
            if (CombinedKey is null)
            {
                throw new ArgumentNullException(nameof(CombinedKey));
            }
            if (CombinedKey.Length != Const.Crypto.AES_KEYSIZE + Const.Crypto.HMAC_SIZE)
            {
                throw new ArgumentException($"Key must be {Const.Crypto.AES_KEYSIZE + Const.Crypto.HMAC_SIZE} bytes long");
            }
            if (CheckHmac(CombinedKey[Const.Crypto.AES_KEYSIZE..]))
            {
                return Decrypt(CombinedKey[..Const.Crypto.AES_KEYSIZE]);
            }
            return null;
        }

        public byte[] Serialize()
        {
            using var MS = new MemoryStream();
            using var BW = MS.GetWriter();
            BW.Write(IV);
            BW.Write(CurveType);
            var PublicX = PublicKey.GetPublicX();
            var PublicY = PublicKey.GetPublicY();
            BW.Write((ushort)PublicX.Length);
            BW.Write(PublicX);
            BW.Write((ushort)PublicY.Length);
            BW.Write(PublicY);
            BW.Write(Payload);
            BW.Write(Hmac);
            BW.Flush();
            return MS.ToArray();
        }

        public void Serialize(Stream Output)
        {
            if (Output is null)
            {
                throw new ArgumentNullException(nameof(Output));
            }
            var Data = Serialize();
            Output.Write(Data, 0, Data.Length);
        }
    }
}
