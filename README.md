# Ed25519

A pure C# implementation of the Ed25519 digital signature algorithm, ported from the [ref10 reference implementation](https://ed25519.cr.yp.to/) and the improved C port by Orson Peters ([`orlp/ed25519`](https://github.com/orlp/ed25519)).

## Features

- **RFC 8032 compliant** - Passes all standard test vectors
- **Pure C#** - No native dependencies
- **High performance** - Uses precomputed tables for fast scalar multiplication
- **PKCS#8 / SPKI support** - Import/export keys in standard formats
- **PEM support** - Read and write PEM-encoded keys

## Installation

```bash
dotnet add package Ed25519
```

## Usage

### Generate a Keypair

```csharp
using Ed25519;

Span<byte> publicKey = stackalloc byte[32];
Span<byte> privateKey = stackalloc byte[64];
Span<byte> seed = stackalloc byte[32];

// Fill seed with 32 bytes of cryptographically secure random data
RandomNumberGenerator.Fill(seed);

Ed25519.CreateKeypair(publicKey, privateKey, seed);
```

### Key Material (important)

- **Seed (32 bytes)**: the secret input to RFC 8032 key generation. This library’s PKCS#8 helpers encode/decode the **seed**.
- **Public key (32 bytes)**: the encoded curve point.
- **Private key (64 bytes)**: this library’s “expanded” private key, derived as `SHA-512(seed)` and stored as:
  - `privateKey[0..31]`: clamped scalar
  - `privateKey[32..63]`: prefix

`Ed25519.Sign(...)` expects the **expanded 64-byte private key** (and optionally the public key).

### API Notes

- **Deterministic signatures**: Ed25519 signing is deterministic for a given (expanded) private key and message (no external randomness needed).
- **Constant-time vs variable-time**:
  - Signing uses constant-time building blocks (`CMov`, etc.).
  - Verification uses variable-time operations (inputs are public).
- **Strict verification**:
  - Verification rejects signatures with non-canonical `S` (must satisfy `S < L`).
  - Verification rejects low-order public keys (small torsion subgroup).
- **Exact-size contracts**:
  - `CreateKeypair`: public key = 32 bytes, private key = 64 bytes, seed = 32 bytes.
  - `Sign`/`Verify`: fixed-size key/signature inputs must be exact size (not oversized).

### Sign a Message

```csharp
byte[] message = "Hello, World!"u8.ToArray();
Span<byte> signature = stackalloc byte[64];

Ed25519.Sign(signature, message, privateKey);
```

### Verify a Signature

```csharp
bool isValid = Ed25519.Verify(signature, message, publicKey);
```

### Import/Export Keys (PKCS#8 and SPKI / RFC 8410)

```csharp
// Export private key seed to PKCS#8 (DER)
byte[] pkcs8 = Pkcs.EncodePkcs8PrivateKey(seed);

// Import seed from PKCS#8 (DER)
byte[] importedSeed = Pkcs.DecodePkcs8PrivateKey(pkcs8);

// Re-expand to this library's 64-byte private key format (and compute public key)
Span<byte> importedPrivateKey = stackalloc byte[64];
Span<byte> importedPublicKey = stackalloc byte[32];
Ed25519.CreateKeypair(importedPublicKey, importedPrivateKey, importedSeed);

// Export public key to SPKI (DER)
byte[] spki = Pkcs.EncodeSubjectPublicKeyInfo(publicKey);

// Import public key from SPKI (DER)
byte[] importedPubKey = Pkcs.DecodeSubjectPublicKeyInfo(spki);
```

### PEM Format

```csharp
// Export to PEM
string privatePem = Pkcs.ExportPrivateKeyPem(seed);      // "PRIVATE KEY" (PKCS#8)
string publicPem = Pkcs.ExportPublicKeyPem(publicKey);   // "PUBLIC KEY" (SPKI)

// Import from PEM (example: private key)
byte[] privateDer = Pkcs.DecodePem(privatePem, "PRIVATE KEY");
byte[] importedSeed = Pkcs.DecodePkcs8PrivateKey(privateDer);
```

## Building Self-Signed Certificates

While Ed25519 keys can be used for signing, .NET's `X509Certificate2` has limited support for Ed25519. For self-signed certificates with Ed25519, you may need to:

1. Generate the Ed25519 keypair using this library
2. Manually construct the TBS (To-Be-Signed) certificate structure
3. Sign it with `Ed25519.Sign()`
4. Encode the final certificate in DER/PEM format

If your goal is *certificate issuance*, this repo includes **CSR (PKCS#10) helpers** in `Pkcs`:

- `Pkcs.EncodePkcs10CertificationRequest(...)` (DER)
- `Pkcs.ExportCsrPem(...)` (PEM)
- `Pkcs.VerifyPkcs10CertificationRequest(...)`

It also supports exporting **encrypted** PKCS#8 PEM (`"ENCRYPTED PRIVATE KEY"`) via `Pkcs.ExportEncryptedPrivateKeyPem(seed, password, iterations)`.

The old encrypted export overload `Pkcs.ExportEncryptedPrivateKeyPem(seed, publicKey, password, iterations)` is kept for compatibility but marked obsolete; the `publicKey` argument is ignored.

## Implementation Notes

This implementation follows the ref10 naming conventions from the original C code. The short names preserve traceability to the reference implementation for auditing purposes.

### Naming Conventions

| Type | Full Name | Description |
|------|-----------|-------------|
| `Fe` | Field Element | Internal type for elements of Z/(2²⁵⁵-19), represented as 10 limbs of 26/25 bits |
| `Sc` | Scalar | Internal type for integers modulo L (group order ≈ 2²⁵²) |
| `Ge` | Group Element | Internal static class for curve point operations |
| `GeP2` | Projective Point | Internal point type in (X:Y:Z) projective coordinates where x=X/Z, y=Y/Z |
| `GeP3` | Extended Point | Internal point type in (X:Y:Z:T) extended coordinates where T=XY/Z |
| `GeP1P1` | Completed Point | Internal intermediate point form (X:Y:Z:T), with x=X/Z, y=Y/T |
| `GePrecomp` | Precomputed Point | Internal affine Niels form (y+x, y-x, 2dxy) for fast fixed-base multiplication |
| `GeCached` | Cached Point | Internal extended Niels form for efficient point addition |

### Precomputed Tables

Two precomputed tables accelerate scalar multiplication:

- **`Base[32,8]`**: Contains `(j+1) × 256^i × B` for `i ∈ [0,31]`, `j ∈ [0,7]`. Used by `ScalarMultBase` for signing.
- **`Bi[8]`**: Contains `(2i+1) × B` for `i ∈ [0,7]`. Used by `DoubleScalarMultVartime` for verification.

### Constant-Time Operations

The implementation uses constant-time conditional moves (`CMov`, `CSwap`) to prevent timing side-channels during signing. Verification uses variable-time operations since all inputs are public.

### Curve Parameters

- **Curve**: Edwards curve `-x² + y² = 1 + dx²y²` where `d = -121665/121666`
- **Base point B**: The standard Ed25519 generator
- **Group order L**: `2²⁵² + 27742317777372353535851937790883648493`

## License

MIT License
