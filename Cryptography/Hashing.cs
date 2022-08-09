using Bitmessage.Global;
using System;

namespace Bitmessage.Cryptography
{
    public class Hashing
    {
        public static byte[] RIPEMD160(byte[] data)
        {
            var hasher = new Org.BouncyCastle.Crypto.Digests.RipeMD160Digest();
            byte[] ret = new byte[hasher.GetDigestSize()];
            hasher.BlockUpdate(data,0,data.Length);
            hasher.DoFinal(ret, 0);
            return ret;
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

        public static byte[] Sha256(byte[] Data)
        {
            if (Data is null)
            {
                throw new ArgumentNullException(nameof(Data));
            }

            using var Hasher = System.Security.Cryptography.SHA256.Create();
            return Hasher.ComputeHash(Data);
        }

        /// <summary>
        /// This is faster than calling <see cref="Sha256(byte[])"/> twice
        /// </summary>
        /// <param name="Data"></param>
        /// <returns></returns>
        public static byte[] DoubleSha256(byte[] Data)
        {
            if (Data is null)
            {
                throw new ArgumentNullException(nameof(Data));
            }
            using var Hasher = System.Security.Cryptography.SHA256.Create();
            return Hasher.ComputeHash(Hasher.ComputeHash(Data));
        }

        public static byte[] HmacSha256(byte[] Salt, byte[] Data)
        {
            if (Salt is null)
            {
                throw new ArgumentNullException(nameof(Salt));
            }

            if (Data is null)
            {
                throw new ArgumentNullException(nameof(Data));
            }

            using var Hasher = new System.Security.Cryptography.HMACSHA256(Salt);
            return Hasher.ComputeHash(Data);
        }

        public static bool ValidateMac(byte[] Mac, byte[] Salt, byte[] Data)
        {
            if (Mac is null)
            {
                throw new ArgumentNullException(nameof(Mac));
            }

            if (Salt is null)
            {
                throw new ArgumentNullException(nameof(Salt));
            }

            if (Data is null)
            {
                throw new ArgumentNullException(nameof(Data));
            }

            return Mac.Length switch
            {
                32 => NativeMethods.CompareBytes(Mac, HmacSha256(Salt, Data)),
                _ => false,
            };
        }
    }
}
