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

        public AddressInfo(byte[] privateEncryptionKey, byte[] privateSigningKey)
        {
            if (privateEncryptionKey is null)
            {
                throw new ArgumentNullException(nameof(privateEncryptionKey));
            }

            if (privateSigningKey is null)
            {
                throw new ArgumentNullException(nameof(privateSigningKey));
            }
            if (privateEncryptionKey.Length != Secp256k1.PRIVKEY_LENGTH)
            {
                throw new ArgumentException($"Key should be {Secp256k1.PRIVKEY_LENGTH} bytes", nameof(privateEncryptionKey));
            }
            if (privateSigningKey.Length != Secp256k1.PRIVKEY_LENGTH)
            {
                throw new ArgumentException($"Key should be {Secp256k1.PRIVKEY_LENGTH} bytes", nameof(privateSigningKey));
            }

            using var generator = new Secp256k1();
            PrivateEncryptionKey = (byte[])privateEncryptionKey.Clone();
            PrivateSigningKey = (byte[])privateSigningKey.Clone();
            PublicEncryptionKey = new byte[Secp256k1.PUBKEY_LENGTH];
            PublicSigningKey = new byte[Secp256k1.PUBKEY_LENGTH];
            if (!generator.PublicKeyCreate(new Span<byte>(PublicEncryptionKey), new Span<byte>(privateEncryptionKey)))
            {
                throw new FormatException($"{nameof(privateEncryptionKey)} is an invalid private key");
            }
            if (!generator.PublicKeyCreate(new Span<byte>(PublicSigningKey), new Span<byte>(privateSigningKey)))
            {
                throw new FormatException($"{nameof(privateSigningKey)} is an invalid private key");
            }
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
            var CombinedKeys = new ECKey(PrivateSigningKey).UncompressedPublicKey
                .Concat(new ECKey(PrivateEncryptionKey).UncompressedPublicKey)
                .ToArray();
            //using var generator = new Secp256k1();
            var Hash = Tools.Sha512(CombinedKeys);
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
            if (PrivateEncryptionKey is null || PrivateSigningKey is null)
            {
                throw new InvalidOperationException("Cannot serialize an address without private keys");
            }
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
            //do not immediately abort to ensure we always read all data.
            //This way we can guarantee that the stream is after the faulty object
            var ok = Generator.PublicKeyCreate(Out, new Span<byte>(PrivateSigningKey));
            Out = new Span<byte>(PublicEncryptionKey);
            ok = ok && Generator.PublicKeyCreate(Out, new Span<byte>(PrivateEncryptionKey));
            AddressVersion = BR.ReadUInt64();
            AddressStream = BR.ReadUInt64();
            if (!ok)
            {
                throw new InvalidDataException("Serialized private keys are invalid");
            }
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

        /// <summary>
        /// Creates an address information object from a public key
        /// </summary>
        /// <param name="publicEncryptionKey">Public encryption key</param>
        /// <param name="publicSigningKey">Public signature key</param>
        /// <returns>Address info with only the public keys filled in</returns>
        /// <remarks>
        /// You need to call <see cref="ComputeEncodedAddress(ulong, ulong)"/>
        /// to get the bitmessage address.
        /// </remarks>
        public static AddressInfo FromPublicKeys(byte[] publicEncryptionKey, byte[] publicSigningKey)
        {
            if (publicEncryptionKey is null)
            {
                throw new ArgumentNullException(nameof(publicEncryptionKey));
            }

            if (publicSigningKey is null)
            {
                throw new ArgumentNullException(nameof(publicSigningKey));
            }
            if (publicEncryptionKey.Length != Secp256k1.PUBKEY_LENGTH)
            {
                throw new ArgumentException($"Key should be {Secp256k1.PUBKEY_LENGTH} bytes. Is it in serialized format?", nameof(publicEncryptionKey));
            }
            if (publicSigningKey.Length != Secp256k1.PUBKEY_LENGTH)
            {
                throw new ArgumentException($"Key should be {Secp256k1.PUBKEY_LENGTH} bytes. Is it in serialized format?", nameof(publicSigningKey));
            }
            return new AddressInfo()
            {
                PublicEncryptionKey = (byte[])publicEncryptionKey.Clone(),
                PublicSigningKey = (byte[])publicEncryptionKey.Clone()
            };
        }
    }
}
