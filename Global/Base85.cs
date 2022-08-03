using System;

namespace Bitmessage.Global
{
    public static class Base85
    {
        public static string Encode(byte[] Data)
        {
            if (Data is null)
            {
                throw new ArgumentNullException(nameof(Data));
            }
            return SimpleBase.Base58.Bitcoin.Encode(new ReadOnlySpan<byte>(Data));
        }

        public static byte[] Decode(string Data)
        {
            if (string.IsNullOrWhiteSpace(Data))
            {
                throw new ArgumentException($"'{nameof(Data)}' cannot be null or whitespace.", nameof(Data));
            }
            return SimpleBase.Base58.Bitcoin.Decode(Data).ToArray();
        }
    }
}
