using Bitmessage.Global;
using Secp256k1Net;
using System;
using System.Linq;

namespace Bitmessage.Cryptography
{
    /// <summary>
    /// Represents an EC keypair
    /// </summary>
    public class ECKey
    {
        private readonly byte[] privateKey, publicKey, publicX, publicY, uncompressedPublicKey;

        /// <summary>
        /// Gets the private key
        /// </summary>
        /// <remarks>This is null if a public key was supplied to the constructor</remarks>
        public byte[] PrivateKey { get => privateKey == null ? null : (byte[])privateKey.Clone(); }

        /// <summary>
        /// Gets the raw public key
        /// </summary>
        public byte[] PublicKey { get => (byte[])publicKey.Clone(); }

        /// <summary>
        /// Gets the serialized, uncompressed public key
        /// </summary>
        public byte[] UncompressedPublicKey { get => (byte[])uncompressedPublicKey.Clone(); }

        /// <summary>
        /// Gets the X component of the public key
        /// </summary>
        public byte[] PublicX { get => (byte[])publicX.Clone(); }

        /// <summary>
        /// Gets the Y component of the public key
        /// </summary>
        public byte[] PublicY { get => (byte[])publicY.Clone(); }

        /// <summary>
        /// Generates a new EC key pair
        /// </summary>
        public ECKey()
        {
            using var generator = new Secp256k1();
            publicKey = new byte[Secp256k1.PUBKEY_LENGTH];
            uncompressedPublicKey = new byte[Secp256k1.SERIALIZED_UNCOMPRESSED_PUBKEY_LENGTH];
            var Output = new Span<byte>(publicKey);
            Span<byte> Input;
            do
            {
                privateKey = Tools.GetCryptoBytes(Secp256k1.PRIVKEY_LENGTH);
                Input = new Span<byte>(privateKey);
            } while (!generator.PublicKeyCreate(Output, Input));
            generator.PublicKeySerialize(new Span<byte>(uncompressedPublicKey), Output);
            publicX = publicKey[..(Secp256k1.PUBKEY_LENGTH / 2)];
            publicY = publicKey[(Secp256k1.PUBKEY_LENGTH / 2)..];
        }

        /// <summary>
        /// Imports an existing EC key
        /// </summary>
        /// <param name="existingKey">EC private key or public key</param>
        /// <remarks>
        /// Private key must be <see cref="Secp256k1.PRIVKEY_LENGTH"/> bytes.
        /// Public key must be either <see cref="Secp256k1.PUBKEY_LENGTH"/>,
        /// <see cref="Secp256k1.SERIALIZED_COMPRESSED_PUBKEY_LENGTH"/>, or
        /// <see cref="Secp256k1.SERIALIZED_UNCOMPRESSED_PUBKEY_LENGTH"/> bytes.
        /// </remarks>
        public ECKey(byte[] existingKey)
        {
            if (existingKey is null)
            {
                throw new ArgumentNullException(nameof(existingKey));
            }
            using var generator = new Secp256k1();
            if (existingKey.Length == Secp256k1.PRIVKEY_LENGTH)
            {
                privateKey = (byte[])existingKey.Clone();
                publicKey = new byte[Secp256k1.PUBKEY_LENGTH];
                var Input = new Span<byte>(privateKey);
                var Output = new Span<byte>(publicKey);
                if (!generator.PublicKeyCreate(Output, Input))
                {
                    throw new FormatException($"Input length ({Secp256k1.PRIVKEY_LENGTH}) suggests a private key but it's not valid");
                }
            }
            else if (existingKey.Length == Secp256k1.PUBKEY_LENGTH)
            {
                publicKey = (byte[])existingKey.Clone();
            }
            else if (existingKey.Length == Secp256k1.SERIALIZED_UNCOMPRESSED_PUBKEY_LENGTH)
            {
                if (!generator.PublicKeyParse(new Span<byte>(publicKey), new Span<byte>(existingKey)))
                {
                    throw new FormatException($"Input length ({Secp256k1.SERIALIZED_UNCOMPRESSED_PUBKEY_LENGTH}) suggests a serialized public key but it's not valid");
                }
            }
            else if (existingKey.Length == Secp256k1.SERIALIZED_COMPRESSED_PUBKEY_LENGTH)
            {
                if (!generator.PublicKeyParse(new Span<byte>(publicKey), new Span<byte>(existingKey)))
                {
                    throw new FormatException($"Input length ({Secp256k1.SERIALIZED_COMPRESSED_PUBKEY_LENGTH}) suggests a serialized compressed public key but it's not valid");
                }
            }
            if (publicKey != null)
            {
                uncompressedPublicKey = new byte[Secp256k1.SERIALIZED_UNCOMPRESSED_PUBKEY_LENGTH];
                generator.PublicKeySerialize(new Span<byte>(uncompressedPublicKey), new Span<byte>(publicKey));
                publicX = publicKey[..(Secp256k1.PUBKEY_LENGTH / 2)];
                publicY = publicKey[(Secp256k1.PUBKEY_LENGTH / 2)..];
            }
        }

        public ECKey(byte[] publicX, byte[] publicY) : this(publicX.Concat(publicY).ToArray())
        {
            //NOOP
        }
    }
}
