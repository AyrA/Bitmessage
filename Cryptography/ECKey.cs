using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using System;
using System.Linq;

namespace Bitmessage.Cryptography
{
    /// <summary>
    /// Represents an EC key
    /// </summary>
    public class ECKey
    {
        public const int PRIVKEY_LENGTH = 32;
        public const int PUBKEY_LENGTH = 64;
        public const int PUBKEY_SERIALIZED_LENGTH = PUBKEY_LENGTH + 1;
        public const int PUBKEY_COMPRESSED_LENGTH = 33;

        /// <summary>
        /// The name of the curve that bitmessage uses
        /// </summary>
        public const string CURVE = "secp256k1";
        /// <summary>
        /// BouncyCastle curve
        /// </summary>
        private static readonly X9ECParameters curve = ECNamedCurveTable.GetByName(CURVE);
        /// <summary>
        /// BouncyCastle curve parameters
        /// </summary>
        private static readonly ECDomainParameters domainParams = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());
        /// <summary>
        /// BouncyCastle RNG
        /// </summary>
        private static readonly SecureRandom rng = new SecureRandom();

        /// <summary>
        /// Gets the private key.
        /// This is null if the object was initialized with <see cref="FromPublic(byte[])"/>
        /// or <see cref="ECKey(ECPoint)"/>
        /// </summary>
        public ECPrivateKeyParameters PrivateKey { get; }
        /// <summary>
        /// Gets the public key
        /// </summary>
        public ECPublicKeyParameters PublicKey { get; }

        /// <summary>
        /// Creates a new random key
        /// </summary>
        public ECKey()
        {
            var keyParams = new ECKeyGenerationParameters(domainParams, rng);
            var generator = new ECKeyPairGenerator("ECDSA");
            generator.Init(keyParams);
            var keyPair = generator.GenerateKeyPair();
            PrivateKey = keyPair.Private as ECPrivateKeyParameters;
            PublicKey = keyPair.Public as ECPublicKeyParameters;
        }

        /// <summary>
        /// Loads a private key and recreates the public key
        /// </summary>
        /// <param name="privateKey">Private key</param>
        public ECKey(byte[] privateKey)
        {
            if (privateKey is null)
            {
                throw new ArgumentNullException(nameof(privateKey));
            }

            var Private = domainParams.ValidatePrivateScalar(new BigInteger(1, privateKey));
            var Public = domainParams.ValidatePublicPoint(curve.G.Multiply(Private));
            Public = Public.Normalize();
            PrivateKey = new ECPrivateKeyParameters(Private, domainParams);
            PublicKey = new ECPublicKeyParameters(Public, domainParams);
        }

        /// <summary>
        /// Creates a new instance with a public key only
        /// </summary>
        /// <param name="publicPoint"></param>
        public ECKey(ECPoint publicPoint)
        {
            if (publicPoint is null)
            {
                throw new ArgumentNullException(nameof(publicPoint));
            }

            PublicKey = new ECPublicKeyParameters(domainParams.ValidatePublicPoint(publicPoint), domainParams);
        }

        /// <summary>
        /// Serializes the private key into a storable format
        /// </summary>
        /// <returns>Private key</returns>
        public byte[] SerializePrivate()
        {
            return PrivateKey.D.ToByteArrayUnsigned();
        }

        /// <summary>
        /// Serializes the public key and optionally compresses it
        /// </summary>
        /// <param name="compress">Compression</param>
        /// <returns>Serialized public key</returns>
        /// <remarks>
        /// A serialized key starts with 0x04 if uncompressed (65 bytes, contains X and Y),
        /// or 0x02 or 0x03 if compressed (33 bytes, contains X only).
        /// The Y component can be recreated because Y² = X³ + 7.
        /// The 2 or 3 decides whether Y is even (2) or odd (3).
        /// </remarks>
        public byte[] SerializePublic(bool compress)
        {
            return PublicKey.Q.GetEncoded(compress);
        }

        public byte[] GetRawPublic()
        {
            return SerializePublic(false)[1..];
        }

        /// <summary>
        /// Does a point multiplication with the current public key
        /// in the way bitmessage wants it
        /// </summary>
        /// <param name="Private">Private key</param>
        /// <returns>Multiplied point</returns>
        /// <remarks>
        /// Bitmessage doesn't uses the intend mechanism (ecdh) for this for some reason
        /// </remarks>
        public ECPoint Multiply(ECKey Private)
        {
            if (Private is null)
            {
                throw new ArgumentNullException(nameof(Private));
            }

            return PublicKey.Q.Multiply(Private.PrivateKey.D).Normalize();
        }

        /// <summary>
        /// Initializes a new instance from a serialized public key
        /// </summary>
        /// <param name="EncodedPublicKey">Serialized public key</param>
        /// <returns>New instance</returns>
        /// <remarks>
        /// Use the constructor if you want to use a private key (32 bytes)
        /// </remarks>
        public static ECKey FromPublic(byte[] EncodedPublicKey)
        {
            if (EncodedPublicKey is null)
            {
                throw new ArgumentNullException(nameof(EncodedPublicKey));
            }

            return new ECKey(curve.Curve.DecodePoint(EncodedPublicKey));
        }
    }
}
