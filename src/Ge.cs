// Ge.cs - Group Element (Curve Point) Operations for Ed25519
// 
// Curve: -x^2 + y^2 = 1 + d*x^2*y^2 where d = -121665/121666
// Based on ref10 implementation by D.J. Bernstein
//
// SPDX-License-Identifier: MIT

using System.Runtime.CompilerServices;

namespace Ed25519;

/// <summary>
/// Projective representation: (X:Y:Z) satisfying x=X/Z, y=Y/Z
/// </summary>
public struct GeP2
{
    public Fe X, Y, Z;

    /// <summary>Set to identity (0, 1).</summary>
    public static void SetZero(out GeP2 h)
    {
        h.X = Fe.Zero();
        h.Y = Fe.One();
        h.Z = Fe.One();
    }
}

/// <summary>
/// Extended representation: (X:Y:Z:T) satisfying x=X/Z, y=Y/Z, XY=ZT
/// </summary>
public struct GeP3
{
    public Fe X, Y, Z, T;

    /// <summary>Set to identity (0, 1).</summary>
    public static void SetZero(out GeP3 h)
    {
        h.X = Fe.Zero();
        h.Y = Fe.One();
        h.Z = Fe.One();
        h.T = Fe.Zero();
    }
}

/// <summary>
/// Completed representation: ((X:Z),(Y:T)) satisfying x=X/Z, y=Y/T
/// </summary>
public struct GeP1P1
{
    public Fe X, Y, Z, T;
}

/// <summary>
/// Duif representation for precomputed points: (y+x, y-x, 2dxy)
/// </summary>
public struct GePrecomp
{
    public Fe YPlusX, YMinusX, Xy2d;

    public static GePrecomp Identity()
    {
        return new GePrecomp
        {
            YPlusX = Fe.One(),
            YMinusX = Fe.One(),
            Xy2d = Fe.Zero()
        };
    }
}

/// <summary>
/// Cached representation for addition: (Y+X, Y-X, Z, 2dT)
/// </summary>
public struct GeCached
{
    public Fe YPlusX, YMinusX, Z, T2d;
}

/// <summary>
/// Group element operations on the Ed25519 curve.
/// </summary>
public static class Ge
{
    // Curve constant d = -121665/121666
    internal static readonly Fe D = new()
    {
        H0 = -10913610, H1 = 13857413, H2 = -15372611, H3 = 6949391, H4 = 114729,
        H5 = -8787816, H6 = -6275908, H7 = -3247719, H8 = -18696448, H9 = -12055116
    };

    // 2*d
    internal static readonly Fe D2 = new()
    {
        H0 = -21827239, H1 = -5839606, H2 = -30745221, H3 = 13898782, H4 = 229458,
        H5 = 15978800, H6 = -12551817, H7 = -6495438, H8 = 29715968, H9 = 9444199
    };

    // sqrt(-1) in the field
    internal static readonly Fe SqrtM1 = new()
    {
        H0 = -32595792, H1 = -7943725, H2 = 9377950, H3 = 3500415, H4 = 12389472,
        H5 = -272473, H6 = -25146209, H7 = -2005654, H8 = 326686, H9 = 11406482
    };

    /// <summary>
    /// r = p (convert P1P1 to P2)
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void P1P1ToP2(out GeP2 r, in GeP1P1 p)
    {
        Fe.Mul(out r.X, in p.X, in p.T);
        Fe.Mul(out r.Y, in p.Y, in p.Z);
        Fe.Mul(out r.Z, in p.Z, in p.T);
    }

    /// <summary>
    /// r = p (convert P1P1 to P3)
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void P1P1ToP3(out GeP3 r, in GeP1P1 p)
    {
        Fe.Mul(out r.X, in p.X, in p.T);
        Fe.Mul(out r.Y, in p.Y, in p.Z);
        Fe.Mul(out r.Z, in p.Z, in p.T);
        Fe.Mul(out r.T, in p.X, in p.Y);
    }

    /// <summary>
    /// r = p (convert P3 to P2)
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void P3ToP2(out GeP2 r, in GeP3 p)
    {
        Fe.Copy(out r.X, in p.X);
        Fe.Copy(out r.Y, in p.Y);
        Fe.Copy(out r.Z, in p.Z);
    }

    /// <summary>
    /// r = p (convert P3 to cached)
    /// </summary>
    public static void P3ToCached(out GeCached r, in GeP3 p)
    {
        Fe.Add(out r.YPlusX, in p.Y, in p.X);
        Fe.Sub(out r.YMinusX, in p.Y, in p.X);
        Fe.Copy(out r.Z, in p.Z);
        Fe.Mul(out r.T2d, in p.T, in D2);
    }

    /// <summary>
    /// r = 2 * p
    /// </summary>
    public static void P2Dbl(out GeP1P1 r, in GeP2 p)
    {
        Fe t0;
        Fe.Sq(out r.X, in p.X);
        Fe.Sq(out r.Z, in p.Y);
        Fe.Sq2(out r.T, in p.Z);
        Fe.Add(out r.Y, in p.X, in p.Y);
        Fe.Sq(out t0, in r.Y);
        Fe.Add(out r.Y, in r.Z, in r.X);
        Fe.Sub(out r.Z, in r.Z, in r.X);
        Fe.Sub(out r.X, in t0, in r.Y);
        Fe.Sub(out r.T, in r.T, in r.Z);
    }

    /// <summary>
    /// r = 2 * p
    /// </summary>
    public static void P3Dbl(out GeP1P1 r, in GeP3 p)
    {
        P3ToP2(out GeP2 q, in p);
        P2Dbl(out r, in q);
    }

    /// <summary>
    /// r = p + q (extended + cached -> completed)
    /// </summary>
    public static void Add(out GeP1P1 r, in GeP3 p, in GeCached q)
    {
        Fe t0;
        Fe.Add(out r.X, in p.Y, in p.X);
        Fe.Sub(out r.Y, in p.Y, in p.X);
        Fe.Mul(out r.Z, in r.X, in q.YPlusX);
        Fe.Mul(out r.Y, in r.Y, in q.YMinusX);
        Fe.Mul(out r.T, in q.T2d, in p.T);
        Fe.Mul(out r.X, in p.Z, in q.Z);
        Fe.Add(out t0, in r.X, in r.X);
        Fe.Sub(out r.X, in r.Z, in r.Y);
        Fe.Add(out r.Y, in r.Z, in r.Y);
        Fe.Add(out r.Z, in t0, in r.T);
        Fe.Sub(out r.T, in t0, in r.T);
    }

    /// <summary>
    /// r = p - q (extended - cached -> completed)
    /// </summary>
    public static void Sub(out GeP1P1 r, in GeP3 p, in GeCached q)
    {
        Fe t0;
        Fe.Add(out r.X, in p.Y, in p.X);
        Fe.Sub(out r.Y, in p.Y, in p.X);
        Fe.Mul(out r.Z, in r.X, in q.YMinusX);
        Fe.Mul(out r.Y, in r.Y, in q.YPlusX);
        Fe.Mul(out r.T, in q.T2d, in p.T);
        Fe.Mul(out r.X, in p.Z, in q.Z);
        Fe.Add(out t0, in r.X, in r.X);
        Fe.Sub(out r.X, in r.Z, in r.Y);
        Fe.Add(out r.Y, in r.Z, in r.Y);
        Fe.Sub(out r.Z, in t0, in r.T);
        Fe.Add(out r.T, in t0, in r.T);
    }

    /// <summary>
    /// r = p + q (mixed addition: extended + precomputed -> completed)
    /// </summary>
    public static void MAdd(out GeP1P1 r, in GeP3 p, in GePrecomp q)
    {
        Fe t0;
        Fe.Add(out r.X, in p.Y, in p.X);
        Fe.Sub(out r.Y, in p.Y, in p.X);
        Fe.Mul(out r.Z, in r.X, in q.YPlusX);
        Fe.Mul(out r.Y, in r.Y, in q.YMinusX);
        Fe.Mul(out r.T, in q.Xy2d, in p.T);
        Fe.Add(out t0, in p.Z, in p.Z);
        Fe.Sub(out r.X, in r.Z, in r.Y);
        Fe.Add(out r.Y, in r.Z, in r.Y);
        Fe.Add(out r.Z, in t0, in r.T);
        Fe.Sub(out r.T, in t0, in r.T);
    }

    /// <summary>
    /// r = p - q (mixed subtraction: extended - precomputed -> completed)
    /// </summary>
    public static void MSub(out GeP1P1 r, in GeP3 p, in GePrecomp q)
    {
        Fe t0;
        Fe.Add(out r.X, in p.Y, in p.X);
        Fe.Sub(out r.Y, in p.Y, in p.X);
        Fe.Mul(out r.Z, in r.X, in q.YMinusX);
        Fe.Mul(out r.Y, in r.Y, in q.YPlusX);
        Fe.Mul(out r.T, in q.Xy2d, in p.T);
        Fe.Add(out t0, in p.Z, in p.Z);
        Fe.Sub(out r.X, in r.Z, in r.Y);
        Fe.Add(out r.Y, in r.Z, in r.Y);
        Fe.Sub(out r.Z, in t0, in r.T);
        Fe.Add(out r.T, in t0, in r.T);
    }

    /// <summary>
    /// Encode a point to 32 bytes (compressed Edwards form).
    /// </summary>
    public static void P3ToBytes(Span<byte> s, in GeP3 h)
    {
        Fe recip, x, y;
        Fe.Invert(out recip, in h.Z);
        Fe.Mul(out x, in h.X, in recip);
        Fe.Mul(out y, in h.Y, in recip);
        Fe.ToBytes(s, in y);
        s[31] ^= (byte)(Fe.IsNegative(in x) << 7);
    }

    /// <summary>
    /// Encode a P2 point to 32 bytes.
    /// </summary>
    public static void ToBytes(Span<byte> s, in GeP2 h)
    {
        Fe recip, x, y;
        Fe.Invert(out recip, in h.Z);
        Fe.Mul(out x, in h.X, in recip);
        Fe.Mul(out y, in h.Y, in recip);
        Fe.ToBytes(s, in y);
        s[31] ^= (byte)(Fe.IsNegative(in x) << 7);
    }

    /// <summary>
    /// Decode a 32-byte point representation to extended coordinates.
    /// Returns 0 on success, -1 if the point is not on the curve.
    /// Negates x for use in verification.
    /// </summary>
    public static int FromBytesNegateVartime(out GeP3 h, ReadOnlySpan<byte> s)
    {
        Fe u, v, v3, vxx, check;

        Fe.FromBytes(out h.Y, s);
        h.Z = Fe.One();
        Fe.Sq(out u, in h.Y);
        Fe.Mul(out v, in u, in D);
        Fe.Sub(out u, in u, in h.Z);    // u = y^2 - 1
        Fe.Add(out v, in v, in h.Z);    // v = dy^2 + 1

        Fe.Sq(out v3, in v);
        Fe.Mul(out v3, in v3, in v);    // v3 = v^3
        Fe.Sq(out h.X, in v3);
        Fe.Mul(out h.X, in h.X, in v);
        Fe.Mul(out h.X, in h.X, in u);  // x = uv^7

        Fe.Pow22523(out h.X, in h.X);   // x = (uv^7)^((q-5)/8)
        Fe.Mul(out h.X, in h.X, in v3);
        Fe.Mul(out h.X, in h.X, in u);  // x = uv^3(uv^7)^((q-5)/8)

        Fe.Sq(out vxx, in h.X);
        Fe.Mul(out vxx, in vxx, in v);
        Fe.Sub(out check, in vxx, in u);  // vx^2 - u

        if (Fe.IsNonZero(in check) != 0)
        {
            Fe.Add(out check, in vxx, in u);  // vx^2 + u
            if (Fe.IsNonZero(in check) != 0)
            {
                h = default;
                return -1;
            }
            Fe.Mul(out h.X, in h.X, in SqrtM1);
        }

        if (Fe.IsNegative(in h.X) == (s[31] >> 7))
        {
            Fe.Neg(out h.X, in h.X);
        }

        Fe.Mul(out h.T, in h.X, in h.Y);
        return 0;
    }

    /// <summary>
    /// Returns true if the point is in the small torsion subgroup.
    /// </summary>
    internal static bool HasSmallOrder(in GeP3 p)
    {
        // Multiply by the cofactor (8) via three doublings; low-order torsion points
        // are exactly the points that collapse to the identity under this operation.
        P3Dbl(out GeP1P1 doubled, in p);
        P1P1ToP2(out GeP2 q, in doubled);

        P2Dbl(out doubled, in q);
        P1P1ToP2(out q, in doubled);

        P2Dbl(out doubled, in q);
        P1P1ToP2(out q, in doubled);

        return IsIdentity(in q);
    }

    /// <summary>
    /// Returns true if the projective point represents the Edwards identity.
    /// </summary>
    internal static bool IsIdentity(in GeP2 p)
    {
        // In projective Edwards coordinates the identity is represented by X = 0 and Y = Z,
        // corresponding to the affine point (0, 1).
        Fe.Sub(out Fe yMinusZ, in p.Y, in p.Z);
        return Fe.IsNonZero(in p.X) == 0 && Fe.IsNonZero(in yMinusZ) == 0;
    }

    /// <summary>
    /// h = a * B where B is the Ed25519 base point.
    /// a must be 32 bytes with a[31] &lt;= 127.
    /// </summary>
    public static void ScalarMultBase(out GeP3 h, ReadOnlySpan<byte> a)
    {
        Span<sbyte> e = stackalloc sbyte[64];

        // Convert scalar to signed radix-16 representation
        for (int i = 0; i < 32; i++)
        {
            e[2 * i] = (sbyte)(a[i] & 15);
            e[2 * i + 1] = (sbyte)((a[i] >> 4) & 15);
        }

        // Carry to make each e[i] in [-8, 8]
        sbyte carry = 0;
        for (int i = 0; i < 63; i++)
        {
            e[i] += carry;
            carry = (sbyte)((e[i] + 8) >> 4);
            e[i] -= (sbyte)(carry << 4);
        }
        e[63] += carry;

        GeP3.SetZero(out h);
        GeP1P1 r;
        GeP2 s;

        // Odd positions (using base table)
        for (int i = 1; i < 64; i += 2)
        {
            SelectPrecomp(out GePrecomp t, i / 2, e[i]);
            MAdd(out r, in h, in t);
            P1P1ToP3(out h, in r);
        }

        // 4 doublings
        P3Dbl(out r, in h);
        P1P1ToP2(out s, in r);
        P2Dbl(out r, in s);
        P1P1ToP2(out s, in r);
        P2Dbl(out r, in s);
        P1P1ToP2(out s, in r);
        P2Dbl(out r, in s);
        P1P1ToP3(out h, in r);

        // Even positions
        for (int i = 0; i < 64; i += 2)
        {
            SelectPrecomp(out GePrecomp t, i / 2, e[i]);
            MAdd(out r, in h, in t);
            P1P1ToP3(out h, in r);
        }
    }

    /// <summary>
    /// r = a * A + b * B (variable-time double scalar multiplication for verification)
    /// </summary>
    public static void DoubleScalarMultVartime(out GeP2 r, ReadOnlySpan<byte> a, in GeP3 A, ReadOnlySpan<byte> b)
    {
        Span<sbyte> aSlide = stackalloc sbyte[256];
        Span<sbyte> bSlide = stackalloc sbyte[256];

        Slide(aSlide, a);
        Slide(bSlide, b);

        // Precompute A, 3A, 5A, 7A, 9A, 11A, 13A, 15A
        Span<GeCached> Ai = stackalloc GeCached[8];
        P3ToCached(out Ai[0], in A);
        P3Dbl(out GeP1P1 t, in A);
        P1P1ToP3(out GeP3 A2, in t);

        for (int i = 0; i < 7; i++)
        {
            Add(out t, in A2, in Ai[i]);
            P1P1ToP3(out GeP3 u, in t);
            P3ToCached(out Ai[i + 1], in u);
        }

        GeP2.SetZero(out r);

        // Find first non-zero
        int startIdx;
        for (startIdx = 255; startIdx >= 0; startIdx--)
        {
            if (aSlide[startIdx] != 0 || bSlide[startIdx] != 0)
                break;
        }

        for (int i = startIdx; i >= 0; i--)
        {
            P2Dbl(out t, in r);

            if (aSlide[i] > 0)
            {
                P1P1ToP3(out GeP3 u, in t);
                Add(out t, in u, in Ai[aSlide[i] / 2]);
            }
            else if (aSlide[i] < 0)
            {
                P1P1ToP3(out GeP3 u, in t);
                Sub(out t, in u, in Ai[(-aSlide[i]) / 2]);
            }

            if (bSlide[i] > 0)
            {
                P1P1ToP3(out GeP3 u, in t);
                MAdd(out t, in u, in GePrecompTables.Bi[bSlide[i] / 2]);
            }
            else if (bSlide[i] < 0)
            {
                P1P1ToP3(out GeP3 u, in t);
                MSub(out t, in u, in GePrecompTables.Bi[(-bSlide[i]) / 2]);
            }

            P1P1ToP2(out r, in t);
        }
    }

    /// <summary>
    /// Compute sliding window representation.
    /// </summary>
    private static void Slide(Span<sbyte> r, ReadOnlySpan<byte> a)
    {
        for (int i = 0; i < 256; i++)
        {
            r[i] = (sbyte)(1 & (a[i >> 3] >> (i & 7)));
        }

        for (int i = 0; i < 256; i++)
        {
            if (r[i] == 0) continue;

            for (int b = 1; b <= 6 && i + b < 256; b++)
            {
                if (r[i + b] == 0) continue;

                if (r[i] + (r[i + b] << b) <= 15)
                {
                    r[i] += (sbyte)(r[i + b] << b);
                    r[i + b] = 0;
                }
                else if (r[i] - (r[i + b] << b) >= -15)
                {
                    r[i] -= (sbyte)(r[i + b] << b);
                    for (int k = i + b; k < 256; k++)
                    {
                        if (r[k] == 0)
                        {
                            r[k] = 1;
                            break;
                        }
                        r[k] = 0;
                    }
                }
                else
                {
                    break;
                }
            }
        }
    }

    /// <summary>
    /// Select a precomputed point in constant time.
    /// </summary>
    private static void SelectPrecomp(out GePrecomp t, int pos, sbyte b)
    {
        // Extract sign bit: 1 if b < 0, 0 otherwise
        // Cast to ulong to match ref10 behavior (sign extend then right shift by 63)
        byte bNegative = (byte)((ulong)b >> 63);
        byte bAbs = (byte)(b - (((-bNegative) & b) << 1));

        t = GePrecomp.Identity();

        CMov(ref t, in GePrecompTables.Base[pos, 0], Equal(bAbs, 1));
        CMov(ref t, in GePrecompTables.Base[pos, 1], Equal(bAbs, 2));
        CMov(ref t, in GePrecompTables.Base[pos, 2], Equal(bAbs, 3));
        CMov(ref t, in GePrecompTables.Base[pos, 3], Equal(bAbs, 4));
        CMov(ref t, in GePrecompTables.Base[pos, 4], Equal(bAbs, 5));
        CMov(ref t, in GePrecompTables.Base[pos, 5], Equal(bAbs, 6));
        CMov(ref t, in GePrecompTables.Base[pos, 6], Equal(bAbs, 7));
        CMov(ref t, in GePrecompTables.Base[pos, 7], Equal(bAbs, 8));

        // Negate if b was negative
        GePrecomp minusT;
        Fe.Copy(out minusT.YPlusX, in t.YMinusX);
        Fe.Copy(out minusT.YMinusX, in t.YPlusX);
        Fe.Neg(out minusT.Xy2d, in t.Xy2d);
        CMov(ref t, in minusT, bNegative);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static byte Equal(byte b, byte c)
    {
        byte x = (byte)(b ^ c);
        uint y = x;
        y -= 1;     // 0xFFFFFFFF if equal, 0..254 otherwise
        y >>= 31;   // 1 if equal, 0 otherwise
        return (byte)y;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void CMov(ref GePrecomp t, in GePrecomp u, byte b)
    {
        Fe.CMov(ref t.YPlusX, in u.YPlusX, b);
        Fe.CMov(ref t.YMinusX, in u.YMinusX, b);
        Fe.CMov(ref t.Xy2d, in u.Xy2d, b);
    }
}
