namespace Bitmessage.Global
{
    public static class Const
    {
        public static class Addr
        {
            /// <summary>
            /// The prefix for bitmessage addresses
            /// </summary>
            public const string PREFIX = "BM-";
            public const ulong DEFAULT_STREAM = 1;
            public const ulong DEFAULT_VERSION = 4;
        }

        public static class EC
        {
            /// <summary>
            /// The name of the curve that bitmessage uses
            /// </summary>
            public const string CURVE = "secp256k1";

            public const int CURVE_IDENTIFIER = 714;

            public const int PRIVKEY_LENGTH = 32;
            public const int PUBKEY_LENGTH = 64;
            public const int PUBKEY_SERIALIZED_LENGTH = PUBKEY_LENGTH + 1;
            public const int PUBKEY_COMPRESSED_LENGTH = 33;
            
            //Key prefixes

            public const byte EVEN_Y = 0x02;
            public const byte ODD_Y = 0x03;
            public const byte FULL_PK = 0x04;
        }

        public static class Crypto
        {
            public const int AES_BLOCKSIZE = 16;
            public const int AES_KEYSIZE = 32;
            public const int HMAC_SIZE = 32;
            public const int RIPE_SIZE = 20;
            public const int SHA256_SIZE = 256 / 8;
            public const int SHA512_SIZE = 512 / 8;
        }
    }
}
