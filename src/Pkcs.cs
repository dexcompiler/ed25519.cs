// Pkcs.cs - PKCS#8 / X.509 / ASN.1 Encoding for Ed25519
// 
// Implements RFC 8410 key encoding for Ed25519.
// Provides PKCS#8 private key and SubjectPublicKeyInfo encoding.
//
// SPDX-License-Identifier: MIT

using System.Text;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;

namespace Ed25519;

/// <summary>
/// ASN.1/DER encoding utilities for Ed25519 keys per RFC 8410.
/// </summary>
public static class Pkcs
{
    private const string Ed25519OidText = "1.3.101.112";

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
        try
        {
            byte[] spkiBytes = spki.ToArray();
            var reader = new AsnReader(spkiBytes, AsnEncodingRules.DER);
            var seq = reader.ReadSequence();

            var algId = seq.ReadSequence();
            string oid = algId.ReadObjectIdentifier();
            if (oid != Ed25519OidText)
                throw new ArgumentException("Invalid SubjectPublicKeyInfo: not Ed25519 OID", nameof(spki));
            if (algId.HasData)
                throw new ArgumentException("Invalid SubjectPublicKeyInfo: Ed25519 parameters must be absent", nameof(spki));

            ReadOnlySpan<byte> publicKey = seq.ReadBitString(out int unusedBitCount);
            if (unusedBitCount != 0)
                throw new ArgumentException("Invalid SubjectPublicKeyInfo: expected 0 unused bits", nameof(spki));
            if (publicKey.Length != Ed25519.PublicKeySize)
                throw new ArgumentException("Invalid SubjectPublicKeyInfo: unexpected public key length", nameof(spki));

            seq.ThrowIfNotEmpty();
            reader.ThrowIfNotEmpty();
            return publicKey.ToArray();
        }
        catch (AsnContentException ex)
        {
            throw new ArgumentException("Invalid SubjectPublicKeyInfo: malformed DER", nameof(spki), ex);
        }
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
        byte[] pkcs8Bytes = pkcs8.ToArray();
        try
        {
            var reader = new AsnReader(pkcs8Bytes, AsnEncodingRules.DER);
            var seq = reader.ReadSequence();

            var version = seq.ReadInteger();
            if (version != 0 && version != 1)
                throw new ArgumentException("Invalid PKCS#8: unsupported version", nameof(pkcs8));

            var algId = seq.ReadSequence();
            string oid = algId.ReadObjectIdentifier();
            if (oid != Ed25519OidText)
                throw new ArgumentException("Invalid PKCS#8: not Ed25519 OID", nameof(pkcs8));
            if (algId.HasData)
                throw new ArgumentException("Invalid PKCS#8: Ed25519 parameters must be absent", nameof(pkcs8));

            ReadOnlySpan<byte> privateKeyOctets = seq.ReadOctetString();
            var privateKeyReader = new AsnReader(privateKeyOctets.ToArray(), AsnEncodingRules.DER);
            ReadOnlySpan<byte> seed = privateKeyReader.ReadOctetString();
            if (seed.Length != Ed25519.SeedSize)
                throw new ArgumentException("Invalid PKCS#8: unexpected seed length", nameof(pkcs8));
            privateKeyReader.ThrowIfNotEmpty();

            while (seq.HasData)
            {
                Asn1Tag tag = seq.PeekTag();
                if (tag.TagClass != TagClass.ContextSpecific)
                    throw new ArgumentException("Invalid PKCS#8: unexpected trailing data", nameof(pkcs8));

                if (tag.TagValue == 0)
                {
                    if (!tag.IsConstructed)
                        throw new ArgumentException("Invalid PKCS#8: malformed attributes field", nameof(pkcs8));
                    seq.ReadEncodedValue();
                    continue;
                }

                if (tag.TagValue == 1)
                {
                    if (tag.IsConstructed)
                        throw new ArgumentException("Invalid PKCS#8: malformed public key field", nameof(pkcs8));
                    seq.ReadEncodedValue();
                    continue;
                }

                throw new ArgumentException("Invalid PKCS#8: unexpected context-specific field", nameof(pkcs8));
            }

            reader.ThrowIfNotEmpty();
            return seed.ToArray();
        }
        catch (AsnContentException ex)
        {
            throw new ArgumentException("Invalid PKCS#8: malformed DER", nameof(pkcs8), ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pkcs8Bytes);
        }
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
        if (string.IsNullOrWhiteSpace(pem))
            throw new ArgumentException("PEM must not be empty", nameof(pem));
        if (string.IsNullOrWhiteSpace(expectedLabel))
            throw new ArgumentException("Expected label must not be empty", nameof(expectedLabel));

        string beginMarker = $"-----BEGIN {expectedLabel}-----";
        string endMarker = $"-----END {expectedLabel}-----";

        string trimmedPem = pem.Trim();
        string normalizedPem = trimmedPem.Replace("\r\n", "\n").Replace('\r', '\n');
        string[] lines = normalizedPem.Split('\n');

        if (lines.Length < 3 || lines[0] != beginMarker || lines[^1] != endMarker)
            throw new ArgumentException($"PEM must contain exactly one '{expectedLabel}' block", nameof(pem));

        var base64Builder = new StringBuilder();
        for (int i = 1; i < lines.Length - 1; i++)
        {
            string line = lines[i];
            if (line.Length == 0)
                throw new ArgumentException("PEM contains empty base64 line", nameof(pem));
            if (line.StartsWith("-----", StringComparison.Ordinal) || line.EndsWith("-----", StringComparison.Ordinal))
                throw new ArgumentException("PEM contains malformed boundary markers", nameof(pem));

            for (int j = 0; j < line.Length; j++)
            {
                if (char.IsWhiteSpace(line[j]))
                    throw new ArgumentException("PEM base64 content must not contain whitespace within lines", nameof(pem));
            }

            base64Builder.Append(line);
        }

        if (base64Builder.Length == 0)
            throw new ArgumentException("PEM contains no base64 content", nameof(pem));

        try
        {
            return Convert.FromBase64String(base64Builder.ToString());
        }
        catch (FormatException ex)
        {
            throw new ArgumentException("PEM contains invalid base64 content", nameof(pem), ex);
        }
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
    /// Export an encrypted private key as PKCS#8 EncryptedPrivateKeyInfo PEM ("ENCRYPTED PRIVATE KEY").
    /// </summary>
    /// <remarks>
    /// Uses PBES2 + PBKDF2(HMAC-SHA256) + AES-256-CBC.
    /// </remarks>
    public static string ExportEncryptedPrivateKeyPem(
        ReadOnlySpan<byte> seed,
        ReadOnlySpan<char> password,
        int iterations = 100_000)
    {
        if (password.IsEmpty)
            throw new ArgumentException("Password must not be empty", nameof(password));
        if (iterations <= 0)
            throw new ArgumentOutOfRangeException(nameof(iterations), "Iterations must be > 0");
        if (seed.Length != Ed25519.SeedSize)
            throw new ArgumentException($"Seed must be {Ed25519.SeedSize} bytes", nameof(seed));

        // Use PKCS#8 PrivateKeyInfo (version 0, no publicKey field) for widest compatibility
        // with downstream PKCS#8 parsing/encryption APIs.
        byte[] pkcs8 = EncodePkcs8PrivateKey(seed);
        try
        {
            // Decode PKCS#8 to a Pkcs8PrivateKeyInfo, then encrypt to EncryptedPrivateKeyInfo.
            // This avoids having to implement PBES2 ASN.1 ourselves.
            var info = Pkcs8PrivateKeyInfo.Decode(pkcs8, out _, skipCopy: false);
            var pbe = new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, iterations);
            byte[] enc = info.Encrypt(password, pbe);

            return EncodePem("ENCRYPTED PRIVATE KEY", enc);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pkcs8);
        }
    }

    /// <summary>
    /// Export an encrypted private key as PKCS#8 EncryptedPrivateKeyInfo PEM ("ENCRYPTED PRIVATE KEY").
    /// </summary>
    /// <remarks>
    /// The <paramref name="publicKey"/> parameter is ignored for encrypted PKCS#8 export.
    /// Use <see cref="ExportEncryptedPrivateKeyPem(ReadOnlySpan{byte}, ReadOnlySpan{char}, int)"/> instead.
    /// </remarks>
    [Obsolete("The publicKey parameter is ignored. Use ExportEncryptedPrivateKeyPem(seed, password, iterations).")]
    public static string ExportEncryptedPrivateKeyPem(
        ReadOnlySpan<byte> seed,
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<char> password,
        int iterations = 100_000)
    {
        if (publicKey.Length != Ed25519.PublicKeySize)
            throw new ArgumentException($"Public key must be {Ed25519.PublicKeySize} bytes", nameof(publicKey));

        return ExportEncryptedPrivateKeyPem(seed, password, iterations);
    }

    /// <summary>
    /// Encode an Ed25519 PKCS#10 CertificationRequest (CSR).
    /// </summary>
    /// <param name="subjectNameDer">DER-encoded X.509 Name (e.g. X500DistinguishedName.RawData).</param>
    /// <param name="publicKey">32-byte Ed25519 public key.</param>
    /// <param name="privateKey">64-byte expanded Ed25519 private key (scalar||prefix).</param>
    /// <returns>DER-encoded CertificationRequest.</returns>
    public static byte[] EncodePkcs10CertificationRequest(
        ReadOnlySpan<byte> subjectNameDer,
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> privateKey)
    {
        if (publicKey.Length != Ed25519.PublicKeySize)
            throw new ArgumentException($"Public key must be {Ed25519.PublicKeySize} bytes", nameof(publicKey));
        if (privateKey.Length != Ed25519.PrivateKeySize)
            throw new ArgumentException($"Private key must be {Ed25519.PrivateKeySize} bytes", nameof(privateKey));
        if (subjectNameDer.IsEmpty)
            throw new ArgumentException("Subject name must not be empty", nameof(subjectNameDer));

        // CertificationRequestInfo ::= SEQUENCE {
        //   version       INTEGER { v1(0) } (v1,...),
        //   subject       Name,
        //   subjectPKInfo SubjectPublicKeyInfo,
        //   attributes    [0] IMPLICIT Attributes
        // }
        //
        // Many implementations expect the attributes field to be present, even if empty.
        // Empty attributes: [0] IMPLICIT SET OF Attribute -> A0 00
        var criWriter = new AsnWriter(AsnEncodingRules.DER);
        using (criWriter.PushSequence())
        {
            criWriter.WriteInteger(0);
            criWriter.WriteEncodedValue(subjectNameDer);
            criWriter.WriteEncodedValue(EncodeSubjectPublicKeyInfo(publicKey));
            criWriter.WriteEncodedValue([0xA0, 0x00]);
        }
        byte[] certificationRequestInfo = criWriter.Encode();

        // signature = Ed25519.Sign(CertificationRequestInfo)
        var signature = new byte[Ed25519.SignatureSize];
        Ed25519.Sign(signature, certificationRequestInfo, publicKey, privateKey);

        // CertificationRequest ::= SEQUENCE {
        //   certificationRequestInfo CertificationRequestInfo,
        //   signatureAlgorithm       AlgorithmIdentifier,
        //   signature                BIT STRING
        // }
        var csrWriter = new AsnWriter(AsnEncodingRules.DER);
        using (csrWriter.PushSequence())
        {
            csrWriter.WriteEncodedValue(certificationRequestInfo);
            csrWriter.WriteEncodedValue(Ed25519AlgorithmIdentifier);
            csrWriter.WriteBitString(signature);
        }

        return csrWriter.Encode();
    }

    /// <summary>
    /// Export an Ed25519 PKCS#10 CSR as PEM ("CERTIFICATE REQUEST").
    /// </summary>
    public static string ExportCsrPem(
        ReadOnlySpan<byte> subjectNameDer,
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> privateKey)
    {
        byte[] der = EncodePkcs10CertificationRequest(subjectNameDer, publicKey, privateKey);
        return EncodePem("CERTIFICATE REQUEST", der);
    }

    /// <summary>
    /// Verify an Ed25519 PKCS#10 CertificationRequest (CSR).
    /// </summary>
    /// <param name="csrDer">DER-encoded CertificationRequest.</param>
    /// <param name="subjectNameDer">DER-encoded X.509 Name from the CSR.</param>
    /// <param name="publicKey">32-byte Ed25519 public key from the CSR.</param>
    /// <returns>True if the signature is valid and the CSR is structurally consistent, otherwise false.</returns>
    public static bool VerifyPkcs10CertificationRequest(
        ReadOnlySpan<byte> csrDer,
        out byte[] subjectNameDer,
        out byte[] publicKey)
    {
        subjectNameDer = [];
        publicKey = [];

        try
        {
            // AsnReader prefers ReadOnlyMemory<byte> in some TFMs; keep a stable backing buffer.
            byte[] csrBytes = csrDer.ToArray();

            // CertificationRequest ::= SEQUENCE {
            //   certificationRequestInfo CertificationRequestInfo,
            //   signatureAlgorithm       AlgorithmIdentifier,
            //   signature                BIT STRING
            // }
            var reader = new AsnReader(csrBytes, AsnEncodingRules.DER);
            var seq = reader.ReadSequence();

            // Keep the exact DER bytes that were signed.
            byte[] criDer = seq.ReadEncodedValue().ToArray();

            // AlgorithmIdentifier must be Ed25519 with absent parameters (RFC 8410).
            var alg = seq.ReadSequence();
            string oid = alg.ReadObjectIdentifier();
            if (oid != "1.3.101.112")
                return false;
            if (alg.HasData)
                return false;

            int unused = 0;
            ReadOnlySpan<byte> sig = seq.ReadBitString(out unused);
            if (unused != 0 || sig.Length != Ed25519.SignatureSize)
                return false;

            seq.ThrowIfNotEmpty();
            reader.ThrowIfNotEmpty();

            // CertificationRequestInfo ::= SEQUENCE {
            //   version       INTEGER { v1(0) },
            //   subject       Name,
            //   subjectPKInfo SubjectPublicKeyInfo,
            //   attributes    [0] IMPLICIT Attributes
            // }
            var criReader = new AsnReader(criDer, AsnEncodingRules.DER);
            var cri = criReader.ReadSequence();

            // version
            var version = cri.ReadInteger();
            if (version != 0)
                return false;

            // subject (Name)
            subjectNameDer = cri.ReadEncodedValue().ToArray();

            // subjectPKInfo (SPKI)
            byte[] spkiDer = cri.ReadEncodedValue().ToArray();
            publicKey = DecodeSubjectPublicKeyInfo(spkiDer);

            // attributes [0] IMPLICIT - allow absent or empty, but if present it must be tag 0.
            if (cri.HasData)
            {
                var tag = cri.PeekTag();
                if (tag.TagClass != TagClass.ContextSpecific || tag.TagValue != 0)
                    return false;

                // Consume it (SET OF Attribute). We don't need to interpret its content for signature verification.
                cri.ReadEncodedValue();
            }

            cri.ThrowIfNotEmpty();
            criReader.ThrowIfNotEmpty();

            return Ed25519.Verify(sig, criDer, publicKey);
        }
        catch (AsnContentException)
        {
            return false;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

}

