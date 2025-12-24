# Ed25519

A pure C# implementation of the Ed25519 digital signature algorithm, ported from the [ref10 reference implementation](https://ed25519.cr.yp.to/).

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

### Import/Export Keys (PKCS#8 and SPKI)

```csharp
// Export private key to PKCS#8
byte[] pkcs8 = Pkcs.ExportPkcs8PrivateKey(privateKey);

// Import private key from PKCS#8
Span<byte> importedPrivateKey = stackalloc byte[64];
Span<byte> importedPublicKey = stackalloc byte[32];
Pkcs.ImportPkcs8PrivateKey(pkcs8, importedPrivateKey, importedPublicKey);

// Export public key to SPKI
byte[] spki = Pkcs.ExportSubjectPublicKeyInfo(publicKey);

// Import public key from SPKI
Span<byte> importedPubKey = stackalloc byte[32];
Pkcs.ImportSubjectPublicKeyInfo(spki, importedPubKey);
```

### PEM Format

```csharp
// Export to PEM
string privatePem = Pkcs.ExportPkcs8PrivateKeyPem(privateKey);
string publicPem = Pkcs.ExportSubjectPublicKeyInfoPem(publicKey);

// Import from PEM
Pkcs.ImportFromPem(privatePem, out byte[] importedKey, out bool isPrivate);
```

## Building Self-Signed Certificates

While Ed25519 keys can be used for signing, .NET's `X509Certificate2` has limited support for Ed25519. For self-signed certificates with Ed25519, you may need to:

1. Generate the Ed25519 keypair using this library
2. Manually construct the TBS (To-Be-Signed) certificate structure
3. Sign it with `Ed25519.Sign()`
4. Encode the final certificate in DER/PEM format

## Implementation Notes

This implementation follows the ref10 naming conventions from the original C code. The short names preserve traceability to the reference implementation for auditing purposes.

### Naming Conventions

| Type | Full Name | Description |
|------|-----------|-------------|
| `Fe` | Field Element | Element of the field Z/(2²⁵⁵-19), represented as 10 limbs of 26/25 bits |
| `Sc` | Scalar | Integer modulo L (the group order ≈ 2²⁵²), used for secret keys |
| `Ge` | Group Element | Static class for curve point operations |
| `GeP2` | Projective Point | Point in (X:Y:Z) projective coordinates where x=X/Z, y=Y/Z |
| `GeP3` | Extended Point | Point in (X:Y:Z:T) extended coordinates where T=XY/Z |
| `GeP1P1` | Completed Point | Intermediate form (X:Y:Z:T) output by additions, with x=X/Z, y=Y/T |
| `GePrecomp` | Precomputed Point | Affine Niels form (y+x, y-x, 2dxy) for fast fixed-base scalar multiplication |
| `GeCached` | Cached Point | Extended Niels form for efficient point addition |

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
