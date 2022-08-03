using System;
using System.Collections.Generic;

namespace Bitmessage.Global
{
    /// <summary>
    /// Compares byte arrays.
    /// This implementation has special routines for cryptographic hashes
    /// </summary>
    public class ByteArrayComparer : IEqualityComparer<byte[]>
    {
        /// <summary>
        /// If enabled, <see cref="GetHashCode(byte[])"/> will only examine at most 4 bytes
        /// and convert them into an integer using <see cref="BitConverter.ToInt32(byte[], int)"/>.
        /// </summary>
        /// <remarks>
        /// Cryptographic hashes show an even distribution,
        /// so this will yield a very good collision resistance (1 in 4 billion).
        /// Enabling this when the data is mostly identical in the first 4 bytes
        /// will yield a slow comparison due to frequent collisions
        /// and thus many unnecessary calls to <see cref="Equals(byte[], byte[])"/>
        /// </remarks>
        public bool AssumeHash { get; }

        public ByteArrayComparer(bool AssumeHash)
        {
            this.AssumeHash = AssumeHash;
        }

        /// <summary>
        /// Compares the two byte arrays for value equality
        /// </summary>
        /// <param name="x">Array 1</param>
        /// <param name="y">Array 2</param>
        /// <returns></returns>
        public bool Equals(byte[] x, byte[] y)
        {
            return NativeMethods.CompareBytes(x, y);
        }

        /// <summary>
        /// Gets a hash code of the given byte array depending on the contents.
        /// The code is generated in a way that tries to minimize false positives
        /// </summary>
        /// <param name="obj">Byte array</param>
        /// <returns>Hash code. Zero if the value is null</returns>
        public int GetHashCode(byte[] obj)
        {
            if (obj is null || obj.Length == 0)
            {
                return 0;
            }
            if (AssumeHash)
            {
                if (obj.Length >= 4)
                {
                    return BitConverter.ToInt32(obj, 0);
                }
            }
            int ret = 0;
            if (obj.Length >= 4)
            {
                //Do not compare too many bytes
                //There comes a point where comparing the arrays will overtake this method in speed.
                //GetHashCode should deliver acceptable results with good speed.
                for (int i = 0; i < Math.Min(400, obj.Length); i += 4)
                {
                    if (obj.Length - i >= 4)
                    {
                        ret ^= BitConverter.ToInt32(obj, i);
                    }
                }
            }
            else
            {
                foreach (var b in obj)
                {
                    ret = (ret << 1) ^ b;
                }
            }
            return ret;
        }
    }
}
