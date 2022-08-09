using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Bitmessage.Cryptography
{
    public static class AES
    {
        public static byte[] Decrypt(byte[] Data, byte[] IV, byte[] Key)
        {
            var Algo = Aes.Create();
            Algo.Key = Key;
            Algo.IV = IV;
            Algo.Mode = CipherMode.CBC;
            Algo.Padding = PaddingMode.PKCS7;
            using var Dec = Algo.CreateDecryptor();
            using var MS = new MemoryStream();
            using var CS = new CryptoStream(MS, Dec, CryptoStreamMode.Write);
            CS.Write(Data, 0, Data.Length);
            CS.FlushFinalBlock();
            return MS.ToArray();
        }

        public static byte[] Encrypt(byte[] Data, byte[] IV, byte[] Key)
        {
            var Algo = Aes.Create();
            Algo.Key = Key;
            Algo.IV = IV;
            Algo.Mode = CipherMode.CBC;
            Algo.Padding = PaddingMode.PKCS7;
            using var Dec = Algo.CreateEncryptor();
            using var MS = new MemoryStream();
            using var CS = new CryptoStream(MS, Dec, CryptoStreamMode.Write);
            CS.Write(Data, 0, Data.Length);
            CS.FlushFinalBlock();
            return MS.ToArray();
        }
    }
}
