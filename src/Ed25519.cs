// Ed25519.cs - Ed25519 Digital Signature Algorithm
// 
// Implements RFC 8032 Ed25519 signatures.
// Based on ref10 implementation by D.J. Bernstein
//
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;

namespace Ed25519;

/// <summary>
/// Ed25519 digital signature algorithm.
/// Provides key generation, signing, and verification.
/// </summary>
public static class Ed25519
{
    // Group order L in little-endian form.
    private static readonly byte[] ScalarOrderL =
    [
        0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58,
        0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
    ];

    /// <summary>Size of a public key in bytes.</summary>
    public const int PublicKeySize = 32;
    
    /// <summary>Size of a private/secret key in bytes (includes hash prefix).</summary>
    public const int PrivateKeySize = 64;
    
    /// <summary>Size of a seed (secret scalar) in bytes.</summary>
    public const int SeedSize = 32;
    
    /// <summary>Size of a signature in bytes.</summary>
    public const int SignatureSize = 64;

    /// <summary>
    /// Create a new Ed25519 keypair from a 32-byte seed.
    /// </summary>
    /// <param name="publicKey">Output: 32-byte public key.</param>
    /// <param name="privateKey">Output: 64-byte private key (includes seed hash).</param>
    /// <param name="seed">Input: 32-byte random seed.</param>
    public static void CreateKeypair(Span<byte> publicKey, Span<byte> privateKey, ReadOnlySpan<byte> seed)
    {
        if (publicKey.Length != PublicKeySize)
            throw new ArgumentException($"Public key buffer must be exactly {PublicKeySize} bytes", nameof(publicKey));
        if (privateKey.Length != PrivateKeySize)
            throw new ArgumentException($"Private key buffer must be exactly {PrivateKeySize} bytes", nameof(privateKey));
        if (seed.Length != SeedSize)
            throw new ArgumentException($"Seed must be exactly {SeedSize} bytes", nameof(seed));

        // Hash the seed to produce the private scalar and prefix
        Span<byte> hash = stackalloc byte[64];
        try
        {
            SHA512.HashData(seed, hash);

            // Clamp the scalar (first 32 bytes)
            hash[0] &= 248;
            hash[31] &= 63;
            hash[31] |= 64;

            // Copy hash to private key
            hash.CopyTo(privateKey);

            // Compute public key: A = [scalar] * B
            Ge.ScalarMultBase(out GeP3 A, hash[..32]);
            Ge.P3ToBytes(publicKey, in A);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hash);
        }
    }

    /// <summary>
    /// Create a keypair and return the seed, public key, and private key.
    /// </summary>
    public static (byte[] PublicKey, byte[] PrivateKey, byte[] Seed) GenerateKeypair()
    {
        var seed = new byte[SeedSize];
        RandomNumberGenerator.Fill(seed);
        
        var publicKey = new byte[PublicKeySize];
        var privateKey = new byte[PrivateKeySize];
        
        CreateKeypair(publicKey, privateKey, seed);
        
        return (publicKey, privateKey, seed);
    }

    /// <summary>
    /// Sign a message with a private key.
    /// </summary>
    /// <param name="signature">Output: 64-byte signature.</param>
    /// <param name="message">The message to sign.</param>
    /// <param name="publicKey">The 32-byte public key.</param>
    /// <param name="privateKey">The 64-byte private key.</param>
    public static void Sign(Span<byte> signature, ReadOnlySpan<byte> message, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> privateKey)
    {
        if (signature.Length != SignatureSize)
            throw new ArgumentException($"Signature buffer must be exactly {SignatureSize} bytes", nameof(signature));
        if (publicKey.Length != PublicKeySize)
            throw new ArgumentException($"Public key must be exactly {PublicKeySize} bytes", nameof(publicKey));
        if (privateKey.Length != PrivateKeySize)
            throw new ArgumentException($"Private key must be exactly {PrivateKeySize} bytes", nameof(privateKey));

        // The private key contains: [0..31] = clamped hash (scalar), [32..63] = prefix
        ReadOnlySpan<byte> prefix = privateKey[32..64];
        ReadOnlySpan<byte> scalar = privateKey[..32];

        // r = SHA512(prefix || message) mod L
        Span<byte> r = stackalloc byte[64];
        Span<byte> h = stackalloc byte[64];
        try
        {
            using (var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA512))
            {
                sha.AppendData(prefix);
                sha.AppendData(message);
                sha.GetHashAndReset(r);
            }
            Sc.Reduce(r);

            // R = [r] * B
            Ge.ScalarMultBase(out GeP3 R, r[..32]);
            Ge.P3ToBytes(signature[..32], in R);

            // h = SHA512(R || publicKey || message) mod L
            using (var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA512))
            {
                sha.AppendData(signature[..32]);
                sha.AppendData(publicKey);
                sha.AppendData(message);
                sha.GetHashAndReset(h);
            }
            Sc.Reduce(h);

            // S = r + h * scalar mod L
            Sc.MulAdd(signature[32..64], h[..32], scalar, r[..32]);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(r);
            CryptographicOperations.ZeroMemory(h);
        }
    }

    /// <summary>
    /// Sign a message with an expanded 64-byte private key (scalar||prefix).
    /// The public key is derived from the private scalar.
    /// </summary>
    /// <param name="signature">Output: 64-byte signature.</param>
    /// <param name="message">The message to sign.</param>
    /// <param name="privateKey">The 64-byte private key (expanded key: scalar||prefix).</param>
    public static void Sign(Span<byte> signature, ReadOnlySpan<byte> message, ReadOnlySpan<byte> privateKey)
    {
        if (privateKey.Length != PrivateKeySize)
            throw new ArgumentException($"Private key buffer must be exactly {PrivateKeySize} bytes", nameof(privateKey));

        // Derive public key: A = [scalar] * B
        Span<byte> publicKey = stackalloc byte[PublicKeySize];
        try
        {
            Ge.ScalarMultBase(out GeP3 A, privateKey[..32]);
            Ge.P3ToBytes(publicKey, in A);

            Sign(signature, message, publicKey, privateKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(publicKey);
        }
    }

    /// <summary>
    /// Sign a message and return the signature as a new array.
    /// </summary>
    public static byte[] Sign(ReadOnlySpan<byte> message, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> privateKey)
    {
        var signature = new byte[SignatureSize];
        Sign(signature, message, publicKey, privateKey);
        return signature;
    }

    /// <summary>
    /// Sign a message with an expanded 64-byte private key (scalar||prefix) and return the signature.
    /// </summary>
    public static byte[] Sign(ReadOnlySpan<byte> message, ReadOnlySpan<byte> privateKey)
    {
        var signature = new byte[SignatureSize];
        // Disambiguate overload: this must call Sign(Span<byte> signature, ..., ReadOnlySpan<byte> privateKey)
        Sign(signature.AsSpan(), message, privateKey);
        return signature;
    }

    /// <summary>
    /// Verify a signature.
    /// </summary>
    /// <param name="signature">The 64-byte signature.</param>
    /// <param name="message">The signed message.</param>
    /// <param name="publicKey">The 32-byte public key.</param>
    /// <returns>True if the signature is valid, false otherwise.</returns>
    public static bool Verify(ReadOnlySpan<byte> signature, ReadOnlySpan<byte> message, ReadOnlySpan<byte> publicKey)
    {
        if (signature.Length != SignatureSize)
            return false;
        if (publicKey.Length != PublicKeySize)
            return false;

        // Check that s is in range (top 3 bits of s must be 0)
        if ((signature[63] & 224) != 0)
            return false;
        if (!IsCanonicalScalar(signature[32..64]))
            return false;

        // Decode public key as point A (negated for subtraction in verification)
        if (Ge.FromBytesNegateVartime(out GeP3 A, publicKey) != 0)
            return false;
        if (Ge.HasSmallOrder(in A))
            return false;

        // h = SHA512(R || publicKey || message) mod L
        Span<byte> h = stackalloc byte[64];
        using (var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA512))
        {
            sha.AppendData(signature[..32]);  // R
            sha.AppendData(publicKey[..32]);
            sha.AppendData(message);
            sha.GetHashAndReset(h);
        }
        Sc.Reduce(h);

        // Compute check = [s] * B - [h] * A = [s] * B + [h] * (-A)
        // Since A was negated during decoding, this becomes [s] * B + [h] * A'
        Ge.DoubleScalarMultVartime(out GeP2 R, h[..32], in A, signature[32..64]);

        // Encode the result and compare with the signature's R component
        Span<byte> checker = stackalloc byte[32];
        Ge.ToBytes(checker, in R);

        return ConstantTimeEquals(checker, signature[..32]);
    }

    /// <summary>
    /// Constant-time comparison of two 32-byte arrays.
    /// </summary>
    private static bool ConstantTimeEquals(ReadOnlySpan<byte> x, ReadOnlySpan<byte> y)
    {
        byte r = 0;
        for (int i = 0; i < 32; i++)
        {
            r |= (byte)(x[i] ^ y[i]);
        }
        return r == 0;
    }

    // Returns true iff s is a canonical scalar in [0, L).
    private static bool IsCanonicalScalar(ReadOnlySpan<byte> s)
    {
        if (s.Length != 32)
            return false;

        // Inputs in Verify are public, so this lexicographic comparison does not
        // introduce a secret-dependent side-channel.
        for (int i = 31; i >= 0; i--)
        {
            if (s[i] < ScalarOrderL[i])
                return true;
            if (s[i] > ScalarOrderL[i])
                return false;
        }

        // Equal to L is non-canonical and must be rejected.
        return false;
    }
}
