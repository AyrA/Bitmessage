using Bitmessage.Global;
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
        public ECKey SigningKey { get; private set; }
        /// <summary>
        /// Private key used for encryption
        /// </summary>
        public ECKey EncryptionKey { get; private set; }

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
            EncryptionKey = new ECKey();
            SigningKey = new ECKey();
            ComputeEncodedAddress(AddressGenerator.DEFAULT_VERSION, AddressGenerator.DEFAULT_STREAM);
        }

        public AddressInfo(byte[] privateSigningKey, byte[] privateEncryptionKey)
        {
            if (privateSigningKey is null)
            {
                throw new ArgumentNullException(nameof(privateSigningKey));
            }
            if (privateEncryptionKey is null)
            {
                throw new ArgumentNullException(nameof(privateEncryptionKey));
            }
            if (privateSigningKey.Length != ECKey.PRIVKEY_LENGTH)
            {
                throw new ArgumentException($"Key should be {ECKey.PRIVKEY_LENGTH} bytes", nameof(privateSigningKey));
            }
            if (privateEncryptionKey.Length != ECKey.PRIVKEY_LENGTH)
            {
                throw new ArgumentException($"Key should be {ECKey.PRIVKEY_LENGTH} bytes", nameof(privateEncryptionKey));
            }

            SigningKey = new ECKey(privateSigningKey);
            EncryptionKey = new ECKey(privateEncryptionKey);
        }

        public AddressInfo(ECKey privSign, ECKey privEnc)
        {
            SigningKey = privSign ?? throw new ArgumentNullException(nameof(privSign));
            EncryptionKey = privEnc ?? throw new ArgumentNullException(nameof(privEnc));
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
            var CombinedKeys = SigningKey.GetRawPublic()
                .Concat(EncryptionKey.GetRawPublic())
                .ToArray();
            //using var generator = new Secp256k1();
            var Hash = Hashing.Sha512(CombinedKeys);
            var ripe = new Org.BouncyCastle.Crypto.Digests.RipeMD160Digest();
            ripe.BlockUpdate(Hash, 0, Hash.Length);
            ripe.DoFinal(Hash, 0);
            Hash = Hash
                .Take(ripe.GetDigestSize())
                .SkipWhile(m => m == 0)
                .ToArray();
            var Data = VarInt.EncodeVarInt(version)
                .Concat(VarInt.EncodeVarInt(stream))
                .Concat(Hash)
                .ToArray();
            var Checksum = Hashing.DoubleSha512(Data).Take(4);
            Data = Data.Concat(Checksum).ToArray();
            AddressVersion = version;
            AddressStream = stream;
            return EncodedAddress = ADDR_PREFIX + Base85.Encode(Data);
        }

        /// <summary>
        /// Serializes the private keys into a stream
        /// </summary>
        /// <param name="Output">Stream</param>
        public void Serialize(Stream Output)
        {
            if (EncryptionKey is null || SigningKey is null)
            {
                throw new InvalidOperationException("Cannot serialize an incomplete address");
            }
            var pSig = SigningKey.SerializePrivate();
            var pEnc = EncryptionKey.SerializePrivate();
            using var BW = Output.GetNativeWriter();
            BW.Write(pSig.Length);
            BW.Write(pSig);
            BW.Write(pEnc.Length);
            BW.Write(pEnc);
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
            SigningKey = new ECKey(BR.ReadBytes(BR.ReadInt32()));
            EncryptionKey = new ECKey(BR.ReadBytes(BR.ReadInt32()));
            AddressVersion = BR.ReadUInt64();
            AddressStream = BR.ReadUInt64();
            ComputeEncodedAddress(AddressVersion, AddressStream);
        }

        public byte[] GetBroadcastHash()
        {
            if (string.IsNullOrEmpty(EncodedAddress))
            {
                ComputeEncodedAddress(AddressVersion, AddressStream);
            }
            return GetBroadcastHash(EncodedAddress);
        }

        public ECKey GetBroadcastKey()
        {
            if (string.IsNullOrEmpty(EncodedAddress))
            {
                ComputeEncodedAddress(AddressVersion, AddressStream);
            }
            return GetBroadcastKey(EncodedAddress);
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
                return Hashing.DoubleSha512(Data).Take(4).SequenceEqual(Checksum);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Gets the hash used for broadcast message encryption and decryption
        /// </summary>
        /// <param name="Address">Bitmessage address</param>
        /// <returns>Broadcast hash</returns>
        /// <remarks>The result will be 64 bytes in length</remarks>
        public static byte[] GetBroadcastHash(string Address)
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
            return Hashing.DoubleSha512(Bytes[..^4]);
        }

        public static ECKey GetBroadcastKey(string Address)
        {
            return new ECKey(GetBroadcastHash(Address)[..32]);
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
        /// Creates an address information object from a serialized public key
        /// </summary>
        /// <param name="publicEncryptionKey">Public encryption key</param>
        /// <param name="publicSigningKey">Public signature key</param>
        /// <returns>Address info with only the public keys filled in</returns>
        /// <remarks>
        /// You need to call <see cref="ComputeEncodedAddress(ulong, ulong)"/>
        /// to get the bitmessage address after calling this function
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
            if (publicEncryptionKey.Length != ECKey.PUBKEY_SERIALIZED_LENGTH && publicEncryptionKey.Length != ECKey.PUBKEY_COMPRESSED_LENGTH)
            {
                throw new ArgumentException($"Key should be {ECKey.PUBKEY_SERIALIZED_LENGTH} or {ECKey.PUBKEY_COMPRESSED_LENGTH} bytes. Is it not in serialized format?", nameof(publicEncryptionKey));
            }
            if (publicSigningKey.Length != ECKey.PUBKEY_SERIALIZED_LENGTH && publicSigningKey.Length != ECKey.PUBKEY_COMPRESSED_LENGTH)
            {
                throw new ArgumentException($"Key should be {ECKey.PUBKEY_SERIALIZED_LENGTH} or {ECKey.PUBKEY_COMPRESSED_LENGTH} bytes. Is it not in serialized format?", nameof(publicSigningKey));
            }
            return new AddressInfo()
            {
                SigningKey = ECKey.FromPublic(publicSigningKey),
                EncryptionKey = ECKey.FromPublic(publicEncryptionKey)
            };
        }
    }
}
