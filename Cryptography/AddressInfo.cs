using Bitmessage.Global;
using DevHawk.Security.Cryptography;
using Secp256k1Net;
using System;
using System.IO;
using System.Linq;

namespace Bitmessage.Cryptography
{
    /// <summary>
    /// Represents a bitmessage address
    /// </summary>
    public class AddressInfo
    {
        /// <summary>
        /// The prefix for bitmessage addresses
        /// </summary>
        public const string ADDR_PREFIX = "BM-";

        /// <summary>
        /// Private key used for signing
        /// </summary>
        public byte[] PrivateSigningKey { get; private set; }
        /// <summary>
        /// Private key used for encryption
        /// </summary>
        public byte[] PrivateEncryptionKey { get; private set; }
        /// <summary>
        /// Public key used for signing
        /// </summary>
        public byte[] PublicSigningKey { get; private set; }
        /// <summary>
        /// Public key used for encryption
        /// </summary>
        public byte[] PublicEncryptionKey { get; private set; }
        /// <summary>
        /// Encoded bitmessage address
        /// </summary>
        /// <remarks>
        /// Apart from the constructor, this is only created/updated when
        /// <see cref="ComputeEncodedAddress(ulong, ulong)"/> is called.
        /// </remarks>
        public string EncodedAddress { get; private set; }
        /// <summary>
        /// Gets the version of <see cref="EncodedAddress"/>
        /// </summary>
        /// <remarks>
        /// Use <see cref="ComputeEncodedAddress(ulong, ulong)"/> to change this value
        /// </remarks>
        public ulong AddressVersion { get; private set; }
        /// <summary>
        /// Gets the stream of <see cref="EncodedAddress"/>
        /// </summary>
        /// <remarks>
        /// Use <see cref="ComputeEncodedAddress(ulong, ulong)"/> to change this value
        /// </remarks>
        public ulong AddressStream { get; private set; }

        /// <summary>
        /// Creates a new instance
        /// </summary>
        /// <remarks>
        /// The address is likely not accepted because the RIPE hash doesn't starts with a nullbyte.
        /// This is an implementation detail of PyBitmessage. The address is still valid in the network.
        /// To get a proper address, use the <see cref="AddressGenerator"/> instead.
        /// </remarks>
        public AddressInfo()
        {

            using var Generator = new Secp256k1();
            CreateSigningKey(Generator);
            CreateEncryptionKey(Generator);
            ComputeEncodedAddress(AddressGenerator.DEFAULT_VERSION, AddressGenerator.DEFAULT_STREAM);
        }

        /// <summary>
        /// Computes the bitmessage address
        /// </summary>
        /// <param name="version">Address version</param>
        /// <param name="stream">Stream number</param>
        /// <returns>Bitmessage address with <see cref="ADDR_PREFIX"/></returns>
        /// <remarks>
        /// An address once generated can be changed to any desired version and stream.
        /// This has no effect on the cryptographic keys.
        /// </remarks>
        public string ComputeEncodedAddress(ulong version, ulong stream)
        {
            using var ripe = new RIPEMD160();
            var Hash = Tools.Sha512(PublicSigningKey.Concat(PublicEncryptionKey).ToArray());
            Hash = ripe.ComputeHash(Hash).SkipWhile(m => m == 0).ToArray();
            var Data = VarInt.EncodeVarInt(version)
                .Concat(VarInt.EncodeVarInt(stream))
                .Concat(Hash)
                .ToArray();
            var Checksum = Tools.DoubleSha512(Data).Take(4);
            Data = Data.Concat(Checksum).ToArray();
            AddressVersion = version;
            AddressStream = stream;
            return EncodedAddress = ADDR_PREFIX + Base85.Encode(Data);
        }

        /// <summary>
        /// Create a signing keypair
        /// </summary>
        /// <param name="Generator">Secp256k1 instance</param>
        public void CreateSigningKey(Secp256k1 Generator)
        {
            PublicSigningKey = new byte[Secp256k1.PUBKEY_LENGTH];
            Span<byte> Input;
            var Output = new Span<byte>(PublicSigningKey);
            do
            {
                PrivateSigningKey = Tools.GetCryptoBytes(Secp256k1.PRIVKEY_LENGTH);
                Input = new Span<byte>(PrivateSigningKey);
            } while (!Generator.PublicKeyCreate(Output, Input));
        }

        /// <summary>
        /// Create an encryption keypair
        /// </summary>
        /// <param name="Generator">Secp256k1 instance</param>
        public void CreateEncryptionKey(Secp256k1 Generator)
        {
            PublicEncryptionKey = new byte[Secp256k1.PUBKEY_LENGTH];
            Span<byte> Input;
            var Output = new Span<byte>(PublicEncryptionKey);
            do
            {
                PrivateEncryptionKey = Tools.GetCryptoBytes(Secp256k1.PRIVKEY_LENGTH);
                Input = new Span<byte>(PrivateEncryptionKey);
            } while (!Generator.PublicKeyCreate(Output, Input));
        }

        /// <summary>
        /// Serializes the private keys into a stream
        /// </summary>
        /// <param name="Output">Stream</param>
        public void Serialize(Stream Output)
        {
            using var BW = Output.GetNativeWriter();
            BW.Write(PrivateSigningKey.Length);
            BW.Write(PrivateSigningKey);
            BW.Write(PrivateEncryptionKey.Length);
            BW.Write(PrivateEncryptionKey);
            BW.Write(AddressVersion);
            BW.Write(AddressStream);
        }

        /// <summary>
        /// Reads private keys from a stream
        /// </summary>
        /// <param name="Input">Stream</param>
        public void Deserialize(Stream Input)
        {
            using var BR = Input.GetNativeReader();
            PrivateSigningKey = BR.ReadBytes(BR.ReadInt32());
            PrivateEncryptionKey = BR.ReadBytes(BR.ReadInt32());
            using var Generator = new Secp256k1();
            var Out = new Span<byte>(PublicSigningKey);
            Generator.PublicKeyCreate(Out, new Span<byte>(PrivateSigningKey));
            Out = new Span<byte>(PublicEncryptionKey);
            Generator.PublicKeyCreate(Out, new Span<byte>(PrivateEncryptionKey));
            AddressVersion = BR.ReadUInt64();
            AddressStream = BR.ReadUInt64();
            ComputeEncodedAddress(AddressVersion, AddressStream);
        }

        /// <summary>
        /// Checks if an address is valid
        /// </summary>
        /// <param name="Address">Bitmessage address</param>
        /// <returns>true, if valid</returns>
        /// <remarks>
        /// Valid means it has to start with <see cref="ADDR_PREFIX"/>
        /// and the checksum (last 4 bytes) has to match.
        /// </remarks>
        public static bool CheckAddress(string Address)
        {
            if (Address is null)
            {
                throw new ArgumentNullException(nameof(Address));
            }
            if (!Address.StartsWith(ADDR_PREFIX))
            {
                throw new FormatException($"Bitmessage addresses start with {ADDR_PREFIX}");
            }
            try
            {
                var Bytes = Base85.Decode(Address[ADDR_PREFIX.Length..]);
                if (Bytes.Length < 5)
                {
                    return false;
                }
                var Data = Bytes.SkipLast(4).ToArray();
                var Checksum = Bytes.TakeLast(4);
                return Tools.DoubleSha512(Data).Take(4).SequenceEqual(Checksum);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Gets the version of an address
        /// </summary>
        /// <param name="Address">Address</param>
        /// <returns>Version</returns>
        /// <remarks>
        /// Make sure you pass the address into <see cref="CheckAddress(string)"/> first.
        /// </remarks>
        public static ulong GetAddressVersion(string Address)
        {
            if (Address is null)
            {
                throw new ArgumentNullException(nameof(Address));
            }
            if (!Address.StartsWith(ADDR_PREFIX))
            {
                throw new FormatException($"Bitmessage addresses start with {ADDR_PREFIX}");
            }
            var Bytes = Base85.Decode(Address[ADDR_PREFIX.Length..]);
            return VarInt.DecodeVarInt(Bytes, 0);
        }

        /// <summary>
        /// Gets the stream of an address
        /// </summary>
        /// <param name="Address">Address</param>
        /// <returns>Stream number</returns>
        /// <remarks>
        /// Make sure you pass the address into <see cref="CheckAddress(string)"/> first.
        /// </remarks>
        public static ulong GetAddressStream(string Address)
        {
            if (Address is null)
            {
                throw new ArgumentNullException(nameof(Address));
            }
            if (!Address.StartsWith(ADDR_PREFIX))
            {
                throw new FormatException($"Bitmessage addresses start with {ADDR_PREFIX}");
            }
            //Getting the second VarInt from the data is easier done with a stream
            using var MS = new MemoryStream(Base85.Decode(Address[ADDR_PREFIX.Length..]), false);
            VarInt.DecodeVarInt(MS);
            return VarInt.DecodeVarInt(MS);
        }
    }
}
