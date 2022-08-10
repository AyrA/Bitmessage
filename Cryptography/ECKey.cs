using Bitmessage.Global;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using System;
using System.IO;

namespace Bitmessage.Cryptography
{
    /// <summary>
    /// Represents an EC key
    /// </summary>
    public class ECKey
    {
        /// <summary>
        /// BouncyCastle curve
        /// </summary>
        private static readonly X9ECParameters curve = ECNamedCurveTable.GetByName(Const.EC.CURVE);
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

        public byte[] Serialize()
        {
            if (PrivateKey != null)
            {
                byte[] ret = new byte[Const.EC.PRIVKEY_LENGTH + 1];
                SerializePrivate().CopyTo(ret, 1);
                return ret;
            }
            return SerializePublic(true);
        }

        public void Serialize(Stream Output)
        {
            if (Output is null)
            {
                throw new ArgumentNullException(nameof(Output));
            }

            var Data = Serialize();
            Output.Write(Data, 0, Data.Length);
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

        public byte[] GetPublicX()
        {
            return GetRawPublic()[..(Const.EC.PUBKEY_LENGTH / 2)];
        }

        public byte[] GetPublicY()
        {
            return GetRawPublic()[(Const.EC.PUBKEY_LENGTH / 2)..];
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

        public byte[] Ecdh(ECKey Private)
        {
            //For some reason, the result of this sometimes differs between us and PyBitmessage

            //*
            var agreement = new ECDHCBasicAgreement();
            /*/
            var ecGen = new ECDHKekGenerator(DigestUtilities.GetDigest("SHA256"));
            var agreement = new ECDHWithKdfBasicAgreement(Org.BouncyCastle.Asn1.Nist.NistObjectIdentifiers.IdAes256Cbc.ToString(), ecGen);
            //*/
            agreement.Init(Private.PrivateKey);
            return agreement.CalculateAgreement(PublicKey).ToByteArrayUnsigned();
        }

        public byte[] Sign(byte[] Data)
        {
            if (Data is null)
            {
                throw new ArgumentNullException(nameof(Data));
            }

            var signer = SignerUtilities.GetSigner("SHA-256withECDSA");
            signer.Init(true, PrivateKey);
            signer.BlockUpdate(Data, 0, Data.Length);
            return signer.GenerateSignature();
        }

        public bool Verify(byte[] Data, byte[] Signature)
        {
            if (Data is null)
            {
                throw new ArgumentNullException(nameof(Data));
            }

            if (Signature is null)
            {
                throw new ArgumentNullException(nameof(Signature));
            }

            var signer = SignerUtilities.GetSigner("SHA-256withECDSA");
            signer.Init(true, PrivateKey);
            signer.BlockUpdate(Data, 0, Data.Length);
            return signer.VerifySignature(Signature);
        }

        public static ECKey Deserialize(byte[] Data)
        {
            if (Data[0] == 0)
            {
                return new ECKey(Data[1..]);
            }
            return FromPublic(Data);
        }

        public static ECKey Deserialize(Stream Source)
        {
            using var BR = Source.GetNativeReader();
            var b = BR.ReadByte();
            if (b == 0)
            {
                return new ECKey(BR.ReadBytes(Const.EC.PRIVKEY_LENGTH));
            }
            var ret = new byte[Const.EC.PUBKEY_LENGTH];
            ret[0] = b;
            BR.ReadBytes(Const.EC.PUBKEY_LENGTH - 1).CopyTo(ret, 1);
            return FromPublic(ret);
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
