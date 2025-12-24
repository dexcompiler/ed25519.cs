// Pkcs.cs - PKCS#8 / X.509 / ASN.1 Encoding for Ed25519
// 
// Implements RFC 8410 key encoding for Ed25519.
// Provides PKCS#8 private key and SubjectPublicKeyInfo encoding.
//
// SPDX-License-Identifier: MIT

using System.Buffers.Binary;
using System.Text;

namespace Ed25519;

/// <summary>
/// ASN.1/DER encoding utilities for Ed25519 keys per RFC 8410.
/// </summary>
public static class Pkcs
{
    // OID for Ed25519: 1.3.101.112
    private static readonly byte[] Ed25519Oid = [0x2B, 0x65, 0x70]; // 1.3.101.112

    // AlgorithmIdentifier for Ed25519 (no parameters)
    // SEQUENCE { OID 1.3.101.112 }
    private static readonly byte[] Ed25519AlgorithmIdentifier =
    [
        0x30, 0x05,          // SEQUENCE, length 5
        0x06, 0x03,          // OID, length 3
        0x2B, 0x65, 0x70     // 1.3.101.112
    ];

    /// <summary>
    /// Encode a public key as SubjectPublicKeyInfo (RFC 8410 Section 3).
    /// </summary>
    /// <param name="publicKey">32-byte Ed25519 public key.</param>
    /// <returns>DER-encoded SubjectPublicKeyInfo.</returns>
    public static byte[] EncodeSubjectPublicKeyInfo(ReadOnlySpan<byte> publicKey)
    {
        if (publicKey.Length != Ed25519.PublicKeySize)
            throw new ArgumentException($"Public key must be {Ed25519.PublicKeySize} bytes", nameof(publicKey));

        // SubjectPublicKeyInfo ::= SEQUENCE {
        //   algorithm        AlgorithmIdentifier,
        //   subjectPublicKey BIT STRING
        // }
        // 
        // For Ed25519:
        // - AlgorithmIdentifier: SEQUENCE { OID 1.3.101.112 } (7 bytes)
        // - BIT STRING: 0x03 + length + 0x00 (no unused bits) + 32 bytes = 35 bytes
        // Total inner: 7 + 35 = 42 bytes
        // SEQUENCE: 0x30 + length (42) + content

        var result = new byte[44]; // 2 (SEQUENCE header) + 7 (AlgId) + 2 (BIT STRING header) + 1 (unused bits) + 32 (key)
        int pos = 0;

        // SEQUENCE
        result[pos++] = 0x30; // SEQUENCE tag
        result[pos++] = 42;   // length

        // AlgorithmIdentifier
        Ed25519AlgorithmIdentifier.CopyTo(result.AsSpan(pos));
        pos += Ed25519AlgorithmIdentifier.Length;

        // BIT STRING containing public key
        result[pos++] = 0x03; // BIT STRING tag
        result[pos++] = 33;   // length (1 + 32)
        result[pos++] = 0x00; // no unused bits
        publicKey.CopyTo(result.AsSpan(pos));

        return result;
    }

    /// <summary>
    /// Decode SubjectPublicKeyInfo to extract the 32-byte public key.
    /// </summary>
    /// <param name="spki">DER-encoded SubjectPublicKeyInfo.</param>
    /// <returns>32-byte Ed25519 public key.</returns>
    public static byte[] DecodeSubjectPublicKeyInfo(ReadOnlySpan<byte> spki)
    {
        // Minimal validation for our expected format
        // Expected structure:
        // SEQUENCE (0x30) len
        //   SEQUENCE (0x30) len  [AlgorithmIdentifier]
        //     OID (0x06) len [Ed25519 OID]
        //   BIT STRING (0x03) len 0x00 [public key]

        if (spki.Length < 44)
            throw new ArgumentException("Invalid SubjectPublicKeyInfo: too short");

        int pos = 0;

        // Outer SEQUENCE
        if (spki[pos++] != 0x30)
            throw new ArgumentException("Invalid SubjectPublicKeyInfo: expected SEQUENCE");

        int outerLen = ReadLength(spki, ref pos);

        // AlgorithmIdentifier SEQUENCE
        if (spki[pos++] != 0x30)
            throw new ArgumentException("Invalid SubjectPublicKeyInfo: expected AlgorithmIdentifier SEQUENCE");

        int algIdLen = ReadLength(spki, ref pos);
        int algIdEnd = pos + algIdLen;

        // OID
        if (spki[pos++] != 0x06)
            throw new ArgumentException("Invalid SubjectPublicKeyInfo: expected OID");

        int oidLen = ReadLength(spki, ref pos);
        if (oidLen != 3 || !spki.Slice(pos, 3).SequenceEqual(Ed25519Oid))
            throw new ArgumentException("Invalid SubjectPublicKeyInfo: not Ed25519 OID");

        pos = algIdEnd; // Skip any parameters (should be none for Ed25519)

        // BIT STRING
        if (spki[pos++] != 0x03)
            throw new ArgumentException("Invalid SubjectPublicKeyInfo: expected BIT STRING");

        int bitStringLen = ReadLength(spki, ref pos);
        if (bitStringLen != 33)
            throw new ArgumentException("Invalid SubjectPublicKeyInfo: unexpected BIT STRING length");

        if (spki[pos++] != 0x00)
            throw new ArgumentException("Invalid SubjectPublicKeyInfo: expected 0 unused bits");

        return spki.Slice(pos, 32).ToArray();
    }

    /// <summary>
    /// Encode a private key as PKCS#8 OneAsymmetricKey (RFC 8410 Section 7).
    /// </summary>
    /// <param name="seed">32-byte Ed25519 seed (private scalar).</param>
    /// <returns>DER-encoded PKCS#8 private key.</returns>
    public static byte[] EncodePkcs8PrivateKey(ReadOnlySpan<byte> seed)
    {
        if (seed.Length != Ed25519.SeedSize)
            throw new ArgumentException($"Seed must be {Ed25519.SeedSize} bytes", nameof(seed));

        // OneAsymmetricKey ::= SEQUENCE {
        //   version                   Version,
        //   privateKeyAlgorithm       AlgorithmIdentifier,
        //   privateKey                OCTET STRING,
        //   attributes           [0]  Attributes OPTIONAL,
        //   publicKey            [1]  PublicKey OPTIONAL
        // }
        //
        // For Ed25519:
        // - version: INTEGER 0 (3 bytes: 0x02 0x01 0x00)
        // - algorithm: AlgorithmIdentifier (7 bytes)
        // - privateKey: OCTET STRING containing OCTET STRING of seed
        //   The inner structure: 0x04 0x20 + 32 bytes = 34 bytes
        //   Wrapped: 0x04 0x22 + 34 bytes = 36 bytes
        // Total inner: 3 + 7 + 36 = 46 bytes

        var result = new byte[48]; // 2 (SEQUENCE header) + 3 (version) + 7 (AlgId) + 2 (OCTET STRING header) + 34 (wrapped key)
        int pos = 0;

        // SEQUENCE
        result[pos++] = 0x30; // SEQUENCE tag
        result[pos++] = 46;   // length

        // Version (INTEGER 0)
        result[pos++] = 0x02; // INTEGER tag
        result[pos++] = 0x01; // length
        result[pos++] = 0x00; // value 0

        // AlgorithmIdentifier
        Ed25519AlgorithmIdentifier.CopyTo(result.AsSpan(pos));
        pos += Ed25519AlgorithmIdentifier.Length;

        // PrivateKey (OCTET STRING containing OCTET STRING of seed)
        // CurvePrivateKey ::= OCTET STRING (RFC 8410)
        result[pos++] = 0x04; // OCTET STRING tag (outer)
        result[pos++] = 34;   // length (2 + 32)
        result[pos++] = 0x04; // OCTET STRING tag (inner - CurvePrivateKey)
        result[pos++] = 32;   // length
        seed.CopyTo(result.AsSpan(pos));

        return result;
    }

    /// <summary>
    /// Encode a private key with its public key as PKCS#8 (RFC 8410 Section 7).
    /// </summary>
    /// <param name="seed">32-byte Ed25519 seed.</param>
    /// <param name="publicKey">32-byte Ed25519 public key.</param>
    /// <returns>DER-encoded PKCS#8 private key with public key attribute.</returns>
    public static byte[] EncodePkcs8PrivateKeyWithPublicKey(ReadOnlySpan<byte> seed, ReadOnlySpan<byte> publicKey)
    {
        if (seed.Length != Ed25519.SeedSize)
            throw new ArgumentException($"Seed must be {Ed25519.SeedSize} bytes", nameof(seed));
        if (publicKey.Length != Ed25519.PublicKeySize)
            throw new ArgumentException($"Public key must be {Ed25519.PublicKeySize} bytes", nameof(publicKey));

        // With public key [1] attribute:
        // publicKey [1] BIT STRING OPTIONAL
        // [1] IMPLICIT BIT STRING = 0x81 + length + 0x00 + 32 bytes = 35 bytes
        // Total inner: 3 + 7 + 36 + 35 = 81 bytes

        var result = new byte[83]; // 2 (SEQUENCE header) + 81 (content)
        int pos = 0;

        // SEQUENCE
        result[pos++] = 0x30; // SEQUENCE tag
        result[pos++] = 81;   // length

        // Version (INTEGER 1 - indicates optional publicKey is present)
        result[pos++] = 0x02; // INTEGER tag
        result[pos++] = 0x01; // length
        result[pos++] = 0x01; // value 1

        // AlgorithmIdentifier
        Ed25519AlgorithmIdentifier.CopyTo(result.AsSpan(pos));
        pos += Ed25519AlgorithmIdentifier.Length;

        // PrivateKey (OCTET STRING containing OCTET STRING of seed)
        result[pos++] = 0x04; // OCTET STRING tag (outer)
        result[pos++] = 34;   // length (2 + 32)
        result[pos++] = 0x04; // OCTET STRING tag (inner)
        result[pos++] = 32;   // length
        seed.CopyTo(result.AsSpan(pos));
        pos += 32;

        // PublicKey [1] (context-specific tag 1, constructed = 0xA1 for explicit, or 0x81 for implicit bit string)
        // RFC 8410 uses [1] IMPLICIT BIT STRING
        result[pos++] = 0x81; // context-specific tag 1, primitive
        result[pos++] = 33;   // length (1 + 32)
        result[pos++] = 0x00; // no unused bits
        publicKey.CopyTo(result.AsSpan(pos));

        return result;
    }

    /// <summary>
    /// Decode a PKCS#8 private key to extract the 32-byte seed.
    /// </summary>
    /// <param name="pkcs8">DER-encoded PKCS#8 private key.</param>
    /// <returns>32-byte Ed25519 seed.</returns>
    public static byte[] DecodePkcs8PrivateKey(ReadOnlySpan<byte> pkcs8)
    {
        if (pkcs8.Length < 48)
            throw new ArgumentException("Invalid PKCS#8: too short");

        int pos = 0;

        // Outer SEQUENCE
        if (pkcs8[pos++] != 0x30)
            throw new ArgumentException("Invalid PKCS#8: expected SEQUENCE");

        int outerLen = ReadLength(pkcs8, ref pos);

        // Version INTEGER
        if (pkcs8[pos++] != 0x02)
            throw new ArgumentException("Invalid PKCS#8: expected INTEGER");

        int versionLen = ReadLength(pkcs8, ref pos);
        pos += versionLen; // Skip version value

        // AlgorithmIdentifier SEQUENCE
        if (pkcs8[pos++] != 0x30)
            throw new ArgumentException("Invalid PKCS#8: expected AlgorithmIdentifier SEQUENCE");

        int algIdLen = ReadLength(pkcs8, ref pos);
        int algIdEnd = pos + algIdLen;

        // OID
        if (pkcs8[pos++] != 0x06)
            throw new ArgumentException("Invalid PKCS#8: expected OID");

        int oidLen = ReadLength(pkcs8, ref pos);
        if (oidLen != 3 || !pkcs8.Slice(pos, 3).SequenceEqual(Ed25519Oid))
            throw new ArgumentException("Invalid PKCS#8: not Ed25519 OID");

        pos = algIdEnd;

        // PrivateKey OCTET STRING (outer)
        if (pkcs8[pos++] != 0x04)
            throw new ArgumentException("Invalid PKCS#8: expected OCTET STRING");

        int outerOctetLen = ReadLength(pkcs8, ref pos);

        // CurvePrivateKey OCTET STRING (inner)
        if (pkcs8[pos++] != 0x04)
            throw new ArgumentException("Invalid PKCS#8: expected inner OCTET STRING");

        int innerOctetLen = ReadLength(pkcs8, ref pos);
        if (innerOctetLen != 32)
            throw new ArgumentException("Invalid PKCS#8: unexpected seed length");

        return pkcs8.Slice(pos, 32).ToArray();
    }

    /// <summary>
    /// Encode data as PEM format.
    /// </summary>
    /// <param name="label">PEM label (e.g., "PUBLIC KEY", "PRIVATE KEY").</param>
    /// <param name="der">DER-encoded data.</param>
    /// <returns>PEM-encoded string.</returns>
    public static string EncodePem(string label, ReadOnlySpan<byte> der)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"-----BEGIN {label}-----");

        string base64 = Convert.ToBase64String(der);
        for (int i = 0; i < base64.Length; i += 64)
        {
            int len = Math.Min(64, base64.Length - i);
            sb.AppendLine(base64.Substring(i, len));
        }

        sb.AppendLine($"-----END {label}-----");
        return sb.ToString();
    }

    /// <summary>
    /// Decode PEM format to DER.
    /// </summary>
    /// <param name="pem">PEM-encoded string.</param>
    /// <param name="expectedLabel">Expected PEM label.</param>
    /// <returns>DER-encoded data.</returns>
    public static byte[] DecodePem(string pem, string expectedLabel)
    {
        string beginMarker = $"-----BEGIN {expectedLabel}-----";
        string endMarker = $"-----END {expectedLabel}-----";

        int beginIndex = pem.IndexOf(beginMarker);
        if (beginIndex < 0)
            throw new ArgumentException($"PEM does not contain '{beginMarker}'");

        int endIndex = pem.IndexOf(endMarker, beginIndex);
        if (endIndex < 0)
            throw new ArgumentException($"PEM does not contain '{endMarker}'");

        int contentStart = beginIndex + beginMarker.Length;
        string base64Content = pem.Substring(contentStart, endIndex - contentStart);

        // Remove whitespace
        base64Content = base64Content.Replace("\r", "").Replace("\n", "").Replace(" ", "");

        return Convert.FromBase64String(base64Content);
    }

    /// <summary>
    /// Export a public key as PEM.
    /// </summary>
    public static string ExportPublicKeyPem(ReadOnlySpan<byte> publicKey)
    {
        byte[] der = EncodeSubjectPublicKeyInfo(publicKey);
        return EncodePem("PUBLIC KEY", der);
    }

    /// <summary>
    /// Export a private key (seed) as PEM.
    /// </summary>
    public static string ExportPrivateKeyPem(ReadOnlySpan<byte> seed)
    {
        byte[] der = EncodePkcs8PrivateKey(seed);
        return EncodePem("PRIVATE KEY", der);
    }

    /// <summary>
    /// Export a private key with public key as PEM.
    /// </summary>
    public static string ExportPrivateKeyPem(ReadOnlySpan<byte> seed, ReadOnlySpan<byte> publicKey)
    {
        byte[] der = EncodePkcs8PrivateKeyWithPublicKey(seed, publicKey);
        return EncodePem("PRIVATE KEY", der);
    }

    /// <summary>
    /// Read a DER length encoding.
    /// </summary>
    private static int ReadLength(ReadOnlySpan<byte> data, ref int pos)
    {
        byte b = data[pos++];
        if (b < 0x80)
            return b;

        int numBytes = b & 0x7F;
        if (numBytes > 4)
            throw new ArgumentException("Length too large");

        int length = 0;
        for (int i = 0; i < numBytes; i++)
        {
            length = (length << 8) | data[pos++];
        }
        return length;
    }
}

