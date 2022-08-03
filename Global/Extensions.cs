using System;
using System.IO;
using System.Text;

namespace Bitmessage.Global
{
    /// <summary>
    /// Extension methods
    /// </summary>
    public static class Extensions
    {
        /// <summary>
        /// Converts a 64 bit number into a 32 bit number.
        /// Throws if out of range
        /// </summary>
        /// <param name="Num">64 bit unsigned number</param>
        /// <returns>32 bit signed number</returns>
        /// <remarks>
        /// This is not a bitwise conversion,
        /// and as such this only returns positive values
        /// </remarks>
        public static int ToInt32(this ulong Num)
        {
            if (Num > int.MaxValue)
            {
                throw new ArgumentOutOfRangeException($"{Num} is too big to fit 32 bit signed integer");
            }
            return (int)Num;
        }

        /// <summary>
        /// Get the builtin binary reader from .NET
        /// </summary>
        /// <param name="S">Stream</param>
        /// <returns>Reader</returns>
        /// <remarks>The returned instance will not close the underlying stream when disposed</remarks>
        public static BinaryReader GetNativeReader(this Stream S)
        {
            return new BinaryReader(S, Encoding.Default, true);
        }

        /// <summary>
        /// Get a binary reader that uses big endian only
        /// </summary>
        /// <param name="S">Stream</param>
        /// <returns>Reader</returns>
        /// <remarks>The returned instance will not close the underlying stream when disposed</remarks>
        public static BigEndianBinaryReader GetReader(this Stream S)
        {
            return new BigEndianBinaryReader(S, Encoding.Default, true);
        }

        /// <summary>
        /// Get the builtin binary writer from .NET
        /// </summary>
        /// <param name="S">Stream</param>
        /// <returns>Writer</returns>
        /// <remarks>The returned instance will not close the underlying stream when disposed</remarks>
        public static BinaryWriter GetNativeWriter(this Stream S)
        {
            return new BinaryWriter(S, Encoding.Default, true);
        }

        /// <summary>
        /// Get a binary writer that uses big endian only
        /// </summary>
        /// <param name="S">Stream</param>
        /// <returns>Writer</returns>
        /// <remarks>The returned instance will not close the underlying stream when disposed</remarks>
        public static BitEndianBinaryWriter GetWriter(this Stream S)
        {
            return new BitEndianBinaryWriter(S, Encoding.Default, true);
        }
    }
}
