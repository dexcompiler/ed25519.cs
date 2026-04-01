// Ed25519Tests.cs - RFC 8032 Test Vectors and Validation
//
// SPDX-License-Identifier: MIT

using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Pkcs;
using System.Formats.Asn1;
using Xunit;

namespace Ed25519.Tests;

/// <summary>
/// Tests for Ed25519 using RFC 8032 test vectors.
/// </summary>
public class Ed25519Tests
{
    // RFC 8032 Section 7.1 - TEST 1
    // SECRET KEY: 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
    // PUBLIC KEY: d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
    // MESSAGE: (empty)
    // SIGNATURE: e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b
    [Fact]
    public void TestVector1_EmptyMessage()
    {
        byte[] seed = Convert.FromHexString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        byte[] expectedPublicKey = Convert.FromHexString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        byte[] message = Array.Empty<byte>();
        byte[] expectedSignature = Convert.FromHexString("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");

        byte[] publicKey = new byte[32];
        byte[] privateKey = new byte[64];
        Ed25519.CreateKeypair(publicKey, privateKey, seed);

        Assert.Equal(expectedPublicKey, publicKey);

        byte[] signature = Ed25519.Sign(message, publicKey, privateKey);
        Assert.Equal(expectedSignature, signature);

        Assert.True(Ed25519.Verify(signature, message, publicKey));
    }

    // RFC 8032 Section 7.1 - TEST 2
    // SECRET KEY: 4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb
    // PUBLIC KEY: 3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c
    // MESSAGE: 72
    // SIGNATURE: 92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00
    [Fact]
    public void TestVector2_SingleByte()
    {
        byte[] seed = Convert.FromHexString("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
        byte[] expectedPublicKey = Convert.FromHexString("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        byte[] message = Convert.FromHexString("72");
        byte[] expectedSignature = Convert.FromHexString("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");

        byte[] publicKey = new byte[32];
        byte[] privateKey = new byte[64];
        Ed25519.CreateKeypair(publicKey, privateKey, seed);

        Assert.Equal(expectedPublicKey, publicKey);

        byte[] signature = Ed25519.Sign(message, publicKey, privateKey);
        Assert.Equal(expectedSignature, signature);

        Assert.True(Ed25519.Verify(signature, message, publicKey));
    }

    // RFC 8032 Section 7.1 - TEST 3
    // SECRET KEY: c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7
    // PUBLIC KEY: fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025
    // MESSAGE: af82
    // SIGNATURE: 6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a
    [Fact]
    public void TestVector3_TwoBytes()
    {
        byte[] seed = Convert.FromHexString("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");
        byte[] expectedPublicKey = Convert.FromHexString("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");
        byte[] message = Convert.FromHexString("af82");
        byte[] expectedSignature = Convert.FromHexString("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a");

        byte[] publicKey = new byte[32];
        byte[] privateKey = new byte[64];
        Ed25519.CreateKeypair(publicKey, privateKey, seed);

        Assert.Equal(expectedPublicKey, publicKey);

        byte[] signature = Ed25519.Sign(message, publicKey, privateKey);
        Assert.Equal(expectedSignature, signature);

        Assert.True(Ed25519.Verify(signature, message, publicKey));
    }

    // RFC 8032 Section 7.1 - 1024-byte message test
    [Fact]
    public void TestVector4_1023ByteMessage()
    {
        byte[] seed = Convert.FromHexString("f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5");
        byte[] expectedPublicKey = Convert.FromHexString("278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e");
        
        // Use the real test vector message
        byte[] message = Convert.FromHexString(
            "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98" +
            "fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d8" +
            "79de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d" +
            "658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc" +
            "1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4fe" +
            "ba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e" +
            "06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbef" +
            "efd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7" +
            "aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed1" +
            "85ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2" +
            "d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24" +
            "554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f270" +
            "88d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc" +
            "2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b07" +
            "07e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128ba" +
            "b27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51a" +
            "ddd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429e" +
            "c96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb7" +
            "51fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c" +
            "42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8" +
            "ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34df" +
            "f7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08" +
            "d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649" +
            "de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e4" +
            "88acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a3" +
            "2ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e" +
            "6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5f" +
            "b93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b5" +
            "0d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1" +
            "369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380d" +
            "b2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c" +
            "0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0"
        );

        byte[] expectedSignature = Convert.FromHexString(
            "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350" +
            "aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03"
        );

        byte[] publicKey = new byte[32];
        byte[] privateKey = new byte[64];
        Ed25519.CreateKeypair(publicKey, privateKey, seed);

        Assert.Equal(expectedPublicKey, publicKey);

        byte[] signature = Ed25519.Sign(message, publicKey, privateKey);
        Assert.Equal(expectedSignature, signature);

        Assert.True(Ed25519.Verify(signature, message, publicKey));
    }

    [Fact]
    public void KeypairGeneration_SignAndVerify()
    {
        // Generate a keypair and verify we can sign and verify
        var (publicKey, privateKey, seed) = Ed25519.GenerateKeypair();

        byte[] message = "Hello, Ed25519!"u8.ToArray();
        byte[] signature = Ed25519.Sign(message, publicKey, privateKey);

        Assert.True(Ed25519.Verify(signature, message, publicKey));
    }

    [Fact]
    public void InvalidSignature_ShouldNotVerify()
    {
        var (publicKey, privateKey, _) = Ed25519.GenerateKeypair();

        byte[] message = "Test message"u8.ToArray();
        byte[] signature = Ed25519.Sign(message, publicKey, privateKey);

        // Flip a bit in the signature
        signature[0] ^= 0x01;

        // Should fail verification
        Assert.False(Ed25519.Verify(signature, message, publicKey));
    }

    [Fact]
    public void SignatureForDifferentMessage_ShouldNotVerify()
    {
        var (publicKey, privateKey, _) = Ed25519.GenerateKeypair();

        byte[] message = "message-1"u8.ToArray();
        byte[] otherMessage = "message-2"u8.ToArray();
        byte[] signature = Ed25519.Sign(message, publicKey, privateKey);

        Assert.False(Ed25519.Verify(signature, otherMessage, publicKey));
    }

    [Fact]
    public void SignatureForDifferentPublicKey_ShouldNotVerify()
    {
        var (publicKey1, privateKey1, _) = Ed25519.GenerateKeypair();
        var (publicKey2, _, _) = Ed25519.GenerateKeypair();

        byte[] message = "hello"u8.ToArray();
        byte[] signature = Ed25519.Sign(message, publicKey1, privateKey1);

        Assert.False(Ed25519.Verify(signature, message, publicKey2));
    }

    [Fact]
    public void SignatureWithNonCanonicalS_ShouldNotVerify()
    {
        var (publicKey, privateKey, _) = Ed25519.GenerateKeypair();

        byte[] message = "Test message"u8.ToArray();
        byte[] signature = Ed25519.Sign(message, publicKey, privateKey);

        // Ed25519.Verify rejects signatures where the top 3 bits of S are non-zero.
        signature[63] |= 0b1110_0000;

        Assert.False(Ed25519.Verify(signature, message, publicKey));
    }

    [Fact]
    public void Verify_WithInvalidPublicKeyEncoding_ShouldReturnFalse()
    {
        // 0xFF.. is extremely unlikely to represent a valid curve point encoding.
        byte[] invalidPublicKey = Enumerable.Repeat((byte)0xFF, 32).ToArray();
        byte[] message = "hello"u8.ToArray();
        byte[] signature = new byte[64]; // doesn't matter

        Assert.False(Ed25519.Verify(signature, message, invalidPublicKey));
    }

    [Fact]
    public void Verify_WithLowOrderPublicKey_ShouldReturnFalse()
    {
        byte[] lowOrderPublicKey = new byte[32];
        lowOrderPublicKey[0] = 0x01; // Edwards identity

        byte[] message = "hello"u8.ToArray();
        byte[] signature = new byte[64];
        signature[0] = 0x01; // Encoded identity for R

        Assert.False(Ed25519.Verify(signature, message, lowOrderPublicKey));
    }

    [Fact]
    public void SignOverload_WithAndWithoutPublicKey_ShouldMatch()
    {
        byte[] seed = Convert.FromHexString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        byte[] publicKey = new byte[32];
        byte[] privateKey = new byte[64];
        Ed25519.CreateKeypair(publicKey, privateKey, seed);

        byte[] message = "same-input"u8.ToArray();

        byte[] sig1 = Ed25519.Sign(message, publicKey, privateKey);
        byte[] sig2 = Ed25519.Sign(message, privateKey);

        Assert.Equal(sig1, sig2);
        Assert.True(Ed25519.Verify(sig1, message, publicKey));
    }

    [Fact]
    public void DeterministicSignatures_SameInputsSameSignature()
    {
        var (publicKey, privateKey, _) = Ed25519.GenerateKeypair();
        byte[] message = "deterministic"u8.ToArray();

        byte[] sig1 = Ed25519.Sign(message, publicKey, privateKey);
        byte[] sig2 = Ed25519.Sign(message, publicKey, privateKey);

        Assert.Equal(sig1, sig2);
    }

    [Fact]
    public void Pkcs8Encoding_RoundTrip()
    {
        byte[] seed = Convert.FromHexString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        byte[] publicKey = new byte[32];
        byte[] privateKey = new byte[64];
        Ed25519.CreateKeypair(publicKey, privateKey, seed);

        // Test PKCS#8 encoding and decoding
        byte[] pkcs8 = Pkcs.EncodePkcs8PrivateKey(seed);
        byte[] decodedSeed = Pkcs.DecodePkcs8PrivateKey(pkcs8);

        Assert.Equal(seed, decodedSeed);

        // Test SPKI encoding and decoding
        byte[] spki = Pkcs.EncodeSubjectPublicKeyInfo(publicKey);
        byte[] decodedPublicKey = Pkcs.DecodeSubjectPublicKeyInfo(spki);

        Assert.Equal(publicKey, decodedPublicKey);
    }

    [Fact]
    public void PemExportImport_RoundTrip()
    {
        byte[] seed = Convert.FromHexString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        byte[] publicKey = new byte[32];
        byte[] privateKey = new byte[64];
        Ed25519.CreateKeypair(publicKey, privateKey, seed);

        // Test PEM export and import for private key
        string privatePem = Pkcs.ExportPrivateKeyPem(seed);
        byte[] privateKeyDer = Pkcs.DecodePem(privatePem, "PRIVATE KEY");
        byte[] recoveredSeed = Pkcs.DecodePkcs8PrivateKey(privateKeyDer);

        Assert.Equal(seed, recoveredSeed);

        // Test PEM export and import for public key
        string publicPem = Pkcs.ExportPublicKeyPem(publicKey);
        byte[] publicKeyDer = Pkcs.DecodePem(publicPem, "PUBLIC KEY");
        byte[] recoveredPublicKey = Pkcs.DecodeSubjectPublicKeyInfo(publicKeyDer);

        Assert.Equal(publicKey, recoveredPublicKey);
    }

    [Fact]
    public void DecodePem_WithWrongLabel_ShouldThrow()
    {
        var (publicKey, _, seed) = Ed25519.GenerateKeypair();

        string privatePem = Pkcs.ExportPrivateKeyPem(seed);
        Assert.Throws<ArgumentException>(() => Pkcs.DecodePem(privatePem, "PUBLIC KEY"));

        string publicPem = Pkcs.ExportPublicKeyPem(publicKey);
        Assert.Throws<ArgumentException>(() => Pkcs.DecodePem(publicPem, "PRIVATE KEY"));
    }

    [Fact]
    public void DecodeSubjectPublicKeyInfo_WithWrongOid_ShouldThrow()
    {
        var (publicKey, _, _) = Ed25519.GenerateKeypair();
        byte[] spki = Pkcs.EncodeSubjectPublicKeyInfo(publicKey);

        // Corrupt the OID bytes (1.3.101.112) -> make it not match.
        // In this encoding, the OID appears as: 06 03 2B 65 70
        int idx = Array.IndexOf(spki, (byte)0x06);
        Assert.True(idx >= 0);
        spki[idx + 2] ^= 0x01; // flip one byte of the OID payload

        Assert.Throws<ArgumentException>(() => Pkcs.DecodeSubjectPublicKeyInfo(spki));
    }

    [Fact]
    public void DecodeSubjectPublicKeyInfo_WithTrailingBytes_ShouldThrow()
    {
        var (publicKey, _, _) = Ed25519.GenerateKeypair();
        byte[] spki = Pkcs.EncodeSubjectPublicKeyInfo(publicKey);
        byte[] withTrailingByte = [.. spki, 0x00];

        Assert.Throws<ArgumentException>(() => Pkcs.DecodeSubjectPublicKeyInfo(withTrailingByte));
    }

    [Fact]
    public void DecodeSubjectPublicKeyInfo_WithNullParameters_ShouldThrow()
    {
        var (publicKey, _, _) = Ed25519.GenerateKeypair();
        byte[] spkiWithNullParams = EncodeSpkiWithNullParameters(publicKey);

        Assert.Throws<ArgumentException>(() => Pkcs.DecodeSubjectPublicKeyInfo(spkiWithNullParams));
    }

    [Fact]
    public void DecodeSubjectPublicKeyInfo_WithNonMinimalLength_ShouldThrow()
    {
        var (publicKey, _, _) = Ed25519.GenerateKeypair();
        byte[] spki = Pkcs.EncodeSubjectPublicKeyInfo(publicKey);
        byte[] nonMinimal = EncodeWithNonMinimalOuterLength(spki);

        Assert.Throws<ArgumentException>(() => Pkcs.DecodeSubjectPublicKeyInfo(nonMinimal));
    }

    [Fact]
    public void DecodeSubjectPublicKeyInfo_WithTruncatedLengthOrValue_ShouldThrow()
    {
        var (publicKey, _, _) = Ed25519.GenerateKeypair();
        byte[] spki = Pkcs.EncodeSubjectPublicKeyInfo(publicKey);

        byte[] truncatedValue = spki[..^1];
        Assert.Throws<ArgumentException>(() => Pkcs.DecodeSubjectPublicKeyInfo(truncatedValue));

        byte[] truncatedByDeclaredLength = spki.ToArray();
        truncatedByDeclaredLength[1]++;
        Assert.Throws<ArgumentException>(() => Pkcs.DecodeSubjectPublicKeyInfo(truncatedByDeclaredLength));
    }

    [Fact]
    public void DecodePkcs8PrivateKey_WithWrongOid_ShouldThrow()
    {
        var (_, _, seed) = Ed25519.GenerateKeypair();
        byte[] pkcs8 = Pkcs.EncodePkcs8PrivateKey(seed);

        // Corrupt the OID bytes (1.3.101.112) -> make it not match.
        // In this encoding, the OID appears as: 06 03 2B 65 70
        int idx = Array.IndexOf(pkcs8, (byte)0x06);
        Assert.True(idx >= 0);
        pkcs8[idx + 2] ^= 0x01; // flip one byte of the OID payload

        Assert.Throws<ArgumentException>(() => Pkcs.DecodePkcs8PrivateKey(pkcs8));
    }

    [Fact]
    public void DecodePkcs8PrivateKey_WithTrailingBytes_ShouldThrow()
    {
        var (_, _, seed) = Ed25519.GenerateKeypair();
        byte[] pkcs8 = Pkcs.EncodePkcs8PrivateKey(seed);
        byte[] withTrailingByte = [.. pkcs8, 0x00];

        Assert.Throws<ArgumentException>(() => Pkcs.DecodePkcs8PrivateKey(withTrailingByte));
    }

    [Fact]
    public void DecodePkcs8PrivateKey_WithNullParameters_ShouldThrow()
    {
        var (_, _, seed) = Ed25519.GenerateKeypair();
        byte[] pkcs8WithNullParams = EncodePkcs8WithNullParameters(seed);

        Assert.Throws<ArgumentException>(() => Pkcs.DecodePkcs8PrivateKey(pkcs8WithNullParams));
    }

    [Fact]
    public void DecodePkcs8PrivateKey_WithNonMinimalLength_ShouldThrow()
    {
        var (_, _, seed) = Ed25519.GenerateKeypair();
        byte[] pkcs8 = Pkcs.EncodePkcs8PrivateKey(seed);
        byte[] nonMinimal = EncodeWithNonMinimalOuterLength(pkcs8);

        Assert.Throws<ArgumentException>(() => Pkcs.DecodePkcs8PrivateKey(nonMinimal));
    }

    [Fact]
    public void DecodePkcs8PrivateKey_WithTruncatedLengthOrValue_ShouldThrow()
    {
        var (_, _, seed) = Ed25519.GenerateKeypair();
        byte[] pkcs8 = Pkcs.EncodePkcs8PrivateKey(seed);

        byte[] truncatedValue = pkcs8[..^1];
        Assert.Throws<ArgumentException>(() => Pkcs.DecodePkcs8PrivateKey(truncatedValue));

        byte[] truncatedByDeclaredLength = pkcs8.ToArray();
        truncatedByDeclaredLength[1]++;
        Assert.Throws<ArgumentException>(() => Pkcs.DecodePkcs8PrivateKey(truncatedByDeclaredLength));
    }

    [Fact]
    public void DecodePem_WithMalformedBoundaries_ShouldThrow()
    {
        var (publicKey, _, _) = Ed25519.GenerateKeypair();
        string pem = Pkcs.ExportPublicKeyPem(publicKey);

        string malformedBegin = pem.Replace("-----BEGIN PUBLIC KEY-----", "----BEGIN PUBLIC KEY-----", StringComparison.Ordinal);
        Assert.Throws<ArgumentException>(() => Pkcs.DecodePem(malformedBegin, "PUBLIC KEY"));

        string malformedEnd = pem.Replace("-----END PUBLIC KEY-----", "-----END PUBLIC KEY----", StringComparison.Ordinal);
        Assert.Throws<ArgumentException>(() => Pkcs.DecodePem(malformedEnd, "PUBLIC KEY"));
    }

    [Fact]
    public void DecodePem_WithSurroundingJunk_ShouldThrow()
    {
        var (publicKey, _, _) = Ed25519.GenerateKeypair();
        string pem = Pkcs.ExportPublicKeyPem(publicKey);

        string withLeadingJunk = $"junk{Environment.NewLine}{pem}";
        Assert.Throws<ArgumentException>(() => Pkcs.DecodePem(withLeadingJunk, "PUBLIC KEY"));

        string withTrailingJunk = $"{pem}{Environment.NewLine}junk";
        Assert.Throws<ArgumentException>(() => Pkcs.DecodePem(withTrailingJunk, "PUBLIC KEY"));
    }

    [Fact]
    public void EncryptedPkcs8Pem_RoundTrip_DecryptAndRecoverSeed()
    {
        var (publicKey, _, seed) = Ed25519.GenerateKeypair();

        const string password = "correct horse battery staple";

        // Keep iterations modest for test speed (still exercises PBES2/PBKDF2/AES path).
        string encPem = Pkcs.ExportEncryptedPrivateKeyPem(seed, password, iterations: 1_000);
        byte[] encDer = Pkcs.DecodePem(encPem, "ENCRYPTED PRIVATE KEY");

        // Decrypt using platform PKCS#8 support and then decode Ed25519 seed.
        var info = Pkcs8PrivateKeyInfo.DecryptAndDecode(password, encDer, out _);
        byte[] pkcs8Der = info.Encode();

        byte[] recoveredSeed = Pkcs.DecodePkcs8PrivateKey(pkcs8Der);
        Assert.Equal(seed, recoveredSeed);
    }

    [Fact]
    public void Pkcs10Csr_RoundTrip_VerifyAndExtract()
    {
        var (publicKey, privateKey, _) = Ed25519.GenerateKeypair();

        // Provide a DER-encoded X.509 Name (subject).
        // (Pkcs helpers operate on DER directly, rather than parsing X500 strings.)
        byte[] subjectNameDer = new X500DistinguishedName("CN=example").RawData;

        byte[] csrDer = Pkcs.EncodePkcs10CertificationRequest(subjectNameDer, publicKey, privateKey);

        Assert.True(Pkcs.VerifyPkcs10CertificationRequest(csrDer, out byte[] recoveredSubjectDer, out byte[] recoveredPublicKey));
        Assert.Equal(subjectNameDer, recoveredSubjectDer);
        Assert.Equal(publicKey, recoveredPublicKey);
    }

    private static byte[] EncodeSpkiWithNullParameters(ReadOnlySpan<byte> publicKey)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier("1.3.101.112");
                writer.WriteNull();
            }

            writer.WriteBitString(publicKey);
        }

        return writer.Encode();
    }

    private static byte[] EncodePkcs8WithNullParameters(ReadOnlySpan<byte> seed)
    {
        var innerPrivateKey = new AsnWriter(AsnEncodingRules.DER);
        innerPrivateKey.WriteOctetString(seed);

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteInteger(0);
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier("1.3.101.112");
                writer.WriteNull();
            }

            writer.WriteOctetString(innerPrivateKey.Encode());
        }

        return writer.Encode();
    }

    private static byte[] EncodeWithNonMinimalOuterLength(ReadOnlySpan<byte> der)
    {
        Assert.True(der.Length >= 2);
        Assert.True(der[0] == 0x30);
        Assert.True(der[1] < 0x80);

        byte[] nonMinimal = new byte[der.Length + 1];
        nonMinimal[0] = der[0];
        nonMinimal[1] = 0x81;
        nonMinimal[2] = der[1];
        der[2..].CopyTo(nonMinimal.AsSpan(3));
        return nonMinimal;
    }
}
