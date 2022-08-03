using Bitmessage.Global;
using System;
using System.Linq;

namespace Bitmessage.Storage
{
    /// <summary>
    /// Index type for <see cref="IndexedStorage"/>
    /// </summary>
    internal class DbIndex
    {
        /// <summary>
        /// XOR value to avoid this entry to have the same hash code as the <see cref="hash"/>
        /// </summary>
        private const int HASHCODE_XORMAP = 0x10F7C019;
        
        /// <summary>
        /// Size in bytes of this instance when serialized to disk
        /// </summary>
        public const int INDEX_BINARY_SIZE = sizeof(long) + IndexedStorage.INDEX_SIZE;

        /// <summary>
        /// hash
        /// </summary>
        private byte[] hash;

        /// <summary>
        /// Precomputed value for <see cref="GetHashCode"/>
        /// </summary>
        private int hashCode;

        /// <summary>
        /// Data offset in the database
        /// </summary>
        public long FileOffset { get; set; }

        /// <summary>
        /// Removal mark
        /// </summary>
        public bool Purge { get; set; }

        /// <summary>
        /// Gets or sets the hash
        /// </summary>
        /// <remarks>Also recomputes <see cref="hashCode"/></remarks>
        public byte[] Hash
        {
            get
            {
                return hash;
            }
            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException(nameof(value));
                }
                if (value.Length != IndexedStorage.INDEX_SIZE)
                {
                    throw new ArgumentException("Value must be 32 bytes");
                }
                hash = (byte[])value.Clone();
                hashCode = BitConverter.ToInt32(hash, 0) ^ HASHCODE_XORMAP;
            }
        }

        /// <summary>
        /// Checks if the supplied value references the same data
        /// </summary>
        /// <param name="index">Database index</param>
        /// <returns>true if <see cref="Hash"/> is identical</returns>
        public bool ReferencesSameObject(DbIndex index)
        {
            if (index is null)
            {
                return false;
            }

            return index.hashCode == hashCode && index.hash.SequenceEqual(hash);
        }

        /// <summary>
        /// Compares this instance to a hash value
        /// </summary>
        /// <param name="Hash">Hash value</param>
        /// <returns>true, if hash is identical to stored hash</returns>
        public bool CompareHash(byte[] Hash)
        {
            return NativeMethods.CompareBytes(Hash, hash);
        }

        /// <summary>
        /// Gets the precomputed hash code
        /// </summary>
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            return hashCode;
        }

        /// <summary>
        /// Checks if the supplied value has the same <see cref="FileOffset"/> and <see cref="Hash"/>
        /// </summary>
        /// <param name="obj">Object</param>
        /// <returns>true, if identical database references</returns>
        public override bool Equals(object obj)
        {
            if (obj is null || obj.GetType() != typeof(DbIndex))
            {
                return false;
            }
            var index = obj as DbIndex;
            return
                index.FileOffset == FileOffset &&
                index.hashCode == hashCode &&
                index.Hash.SequenceEqual(Hash);
        }

        /// <summary>
        /// Compares two DbIndex instances
        /// </summary>
        /// <param name="A">Instance A</param>
        /// <param name="B">Instance B</param>
        /// <returns>A.Equals(B)</returns>
        public static bool operator ==(DbIndex A, DbIndex B)
        {
            return Equals(A, B);
        }

        /// <summary>
        /// Compares two DbIndex instances
        /// </summary>
        /// <param name="A">Instance A</param>
        /// <param name="B">Instance B</param>
        /// <returns>!A.Equals(B)</returns>
        public static bool operator !=(DbIndex A, DbIndex B)
        {
            return !Equals(A, B);
        }
    }
}
