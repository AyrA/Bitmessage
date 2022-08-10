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
        /// Getsy or sets the address label
        /// </summary>
        public string Label { get; set; }

        /// <summary>
        /// Gets or sets whether the address is enabled
        /// </summary>
        public bool Enabled { get; set; }

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
            ComputeEncodedAddress();
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
            if (privateSigningKey.Length != Const.EC.PRIVKEY_LENGTH)
            {
                throw new ArgumentException($"Key should be {Const.EC.PRIVKEY_LENGTH} bytes", nameof(privateSigningKey));
            }
            if (privateEncryptionKey.Length != Const.EC.PRIVKEY_LENGTH)
            {
                throw new ArgumentException($"Key should be {Const.EC.PRIVKEY_LENGTH} bytes", nameof(privateEncryptionKey));
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
        /// <returns>Bitmessage address with <see cref="Const.Addr.PREFIX"/></returns>
        /// <remarks>
        /// An address once generated can be changed to any desired version and stream.
        /// This has no effect on the cryptographic keys.
        /// </remarks>
        public string ComputeEncodedAddress(ulong version = Const.Addr.DEFAULT_VERSION, ulong stream= Const.Addr.DEFAULT_STREAM)
        {
            var CombinedKeys = SigningKey.SerializePublic(false)
                .Concat(EncryptionKey.SerializePublic(false))
                .ToArray();
            EncodedAddress = GetAddress(Hashing.RIPEMD160(Hashing.Sha512(CombinedKeys)), version, stream);
            AddressVersion = version;
            AddressStream = stream;
            return EncodedAddress;
        }

        /// <summary>
        /// Serializes the private keys into a stream
        /// </summary>
        /// <param name="Output">Stream</param>
        public void Serialize(Stream Output)
        {
            if (Output is null)
            {
                throw new ArgumentNullException(nameof(Output));
            }

            if (EncryptionKey is null || SigningKey is null)
            {
                throw new InvalidOperationException("Cannot serialize an incomplete address");
            }
            SigningKey.Serialize(Output);
            EncryptionKey.Serialize(Output);
            using var BW = Output.GetNativeWriter();
            BW.Write(AddressVersion);
            BW.Write(AddressStream);
            BW.Write(Enabled);
            BW.Write(Label ?? "");
        }

        /// <summary>
        /// Reads private keys from a stream
        /// </summary>
        /// <param name="Input">Stream</param>
        public void Deserialize(Stream Input)
        {
            if (Input is null)
            {
                throw new ArgumentNullException(nameof(Input));
            }

            SigningKey = ECKey.Deserialize(Input);
            EncryptionKey = ECKey.Deserialize(Input);
            using var BR = Input.GetNativeReader();
            AddressVersion = BR.ReadUInt64();
            AddressStream = BR.ReadUInt64();
            Enabled = BR.ReadBoolean();
            Label = BR.ReadString();
            ComputeEncodedAddress(AddressVersion, AddressStream);
        }

        /// <summary>
        /// Gets the hash that is used for decrypting broadcasts and verify the hmac
        /// </summary>
        /// <returns>SHA512</returns>
        public byte[] GetBroadcastHash()
        {
            if (string.IsNullOrEmpty(EncodedAddress))
            {
                ComputeEncodedAddress(AddressVersion, AddressStream);
            }
            return GetBroadcastHash(EncodedAddress);
        }

        /// <summary>
        /// Gets the EC key used for encrypting broadcasts.
        /// To also get the hmac key use <see cref="GetBroadcastHash"/>
        /// </summary>
        /// <returns>Broadcast EC key</returns>
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
        /// Valid means it has to start with <see cref="Const.Addr.PREFIX"/>
        /// and the checksum (last 4 bytes) has to match.
        /// </remarks>
        public static bool CheckAddress(string Address)
        {
            if (Address is null)
            {
                throw new ArgumentNullException(nameof(Address));
            }
            if (!Address.StartsWith(Const.Addr.PREFIX))
            {
                throw new FormatException($"Bitmessage addresses start with {Const.Addr.PREFIX}");
            }
            try
            {
                var Bytes = Base85.Decode(Address[Const.Addr.PREFIX.Length..]);
                if (Bytes.Length < 5)
                {
                    return false;
                }
                var Data = Bytes[..^4];
                var Checksum = Bytes[^4..];
                return Hashing.DoubleSha512(Data)[..4].SequenceEqual(Checksum);
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
            if (!Address.StartsWith(Const.Addr.PREFIX))
            {
                throw new FormatException($"Bitmessage addresses start with {Const.Addr.PREFIX}");
            }
            //Address data minus the checksum
            var Bytes = Base85.Decode(Address[Const.Addr.PREFIX.Length..])[..^4];

            //Annoyingly, the broadcast hash is generated from the full ripe hash,
            //not the truncated one that is actually part of the address string.
            //This means we need to insert leading zeroes to extend it to 160 bits (20 bytes).
            //This also means we need to decode and immediately re-encode
            //the var_int someone was a huge fan of.
            //This is not documented either. You're supposed to just magically know this.
            //You can find how it's done by looking at "decodeAddress" in "addresses.py"
            using var MS = new MemoryStream(Bytes, false);
            using var BR = MS.GetReader();
            var version = BR.ReadVarInt();
            var OutBuffer = VarInt.EncodeVarInt(version) //Version
                .Concat(VarInt.EncodeVarInt(BR.ReadVarInt())) //Stream
                .Concat(new byte[20]) //Reserved space for ripemd160
                .ToArray();
            //All remaining data is the hash. Copy and preserve leading zeros
            var Ripe = BR.ReadBytes((int)(MS.Length - MS.Position));
            Ripe.CopyTo(OutBuffer, OutBuffer.Length - Ripe.Length);
            //Do single hash only for old addresses
            return version < 4 ? Hashing.Sha512(OutBuffer) : Hashing.DoubleSha512(OutBuffer);
        }

        /// <summary>
        /// Gets the EC key used for encrypting broadcasts.
        /// To also get the hmac key use <see cref="GetBroadcastHash(string)"/>
        /// </summary>
        /// <param name="Address">Bitmessage address</param>
        /// <returns>Broadcast EC key</returns>
        public static ECKey GetBroadcastKey(string Address)
        {
            return new ECKey(GetBroadcastHash(Address)[..32]);
        }

        /// <summary>
        /// Gets the bitmessage address from the given information
        /// </summary>
        /// <param name="ripe">ripe hash (truncated or not)</param>
        /// <param name="version">Address version</param>
        /// <param name="stream">Stream number</param>
        /// <returns>Bitmessage address</returns>
        public static string GetAddress(byte[] ripe, ulong version = Const.Addr.DEFAULT_VERSION, ulong stream = Const.Addr.DEFAULT_STREAM)
        {
            if (ripe is null)
            {
                throw new ArgumentNullException(nameof(ripe));
            }
            var Data = VarInt.EncodeVarInt(version)
                .Concat(VarInt.EncodeVarInt(stream))
                .Concat(ripe.SkipWhile(m => m == 0))
                .ToArray();
            var Checksum = Hashing.DoubleSha512(Data)[..4];
            return Const.Addr.PREFIX + Base85.Encode(Data.Concat(Checksum).ToArray());
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
            if (!Address.StartsWith(Const.Addr.PREFIX))
            {
                throw new FormatException($"Bitmessage addresses start with {Const.Addr.PREFIX}");
            }
            var Bytes = Base85.Decode(Address[Const.Addr.PREFIX.Length..]);
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
            if (!Address.StartsWith(Const.Addr.PREFIX))
            {
                throw new FormatException($"Bitmessage addresses start with {Const.Addr.PREFIX}");
            }
            //Getting the second VarInt from the data is easier done with a stream
            using var MS = new MemoryStream(Base85.Decode(Address[Const.Addr.PREFIX.Length..]), false);
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
            if (publicEncryptionKey.Length != Const.EC.PUBKEY_SERIALIZED_LENGTH && publicEncryptionKey.Length != Const.EC.PUBKEY_COMPRESSED_LENGTH)
            {
                throw new ArgumentException($"Key should be {Const.EC.PUBKEY_SERIALIZED_LENGTH} or {Const.EC.PUBKEY_COMPRESSED_LENGTH} bytes. Is it not in serialized format?", nameof(publicEncryptionKey));
            }
            if (publicSigningKey.Length != Const.EC.PUBKEY_SERIALIZED_LENGTH && publicSigningKey.Length != Const.EC.PUBKEY_COMPRESSED_LENGTH)
            {
                throw new ArgumentException($"Key should be {Const.EC.PUBKEY_SERIALIZED_LENGTH} or {Const.EC.PUBKEY_COMPRESSED_LENGTH} bytes. Is it not in serialized format?", nameof(publicSigningKey));
            }
            return new AddressInfo()
            {
                SigningKey = ECKey.FromPublic(publicSigningKey),
                EncryptionKey = ECKey.FromPublic(publicEncryptionKey)
            };
        }
    }
}
