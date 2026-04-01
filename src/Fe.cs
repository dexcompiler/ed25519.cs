// Fe.cs - Field Element Arithmetic for Ed25519
// 
// Field: Z/(2^255-19)
// Representation: 10 limbs of 26/25 alternating bits
// Based on ref10 implementation by D.J. Bernstein
//
// SPDX-License-Identifier: MIT

using System.Runtime.CompilerServices;

namespace Ed25519;

/// <summary>
/// Field element in Z/(2^255-19).
/// Represented as 10 signed 32-bit integers (limbs) where:
/// t[0]+2^26*t[1]+2^51*t[2]+2^77*t[3]+2^102*t[4]+...+2^230*t[9]
/// Limb bounds vary depending on context (see individual method docs).
/// </summary>
internal struct Fe
{
    // 10 limbs representing the field element
    // Even indices (0,2,4,6,8) hold 26-bit values
    // Odd indices (1,3,5,7,9) hold 25-bit values
    public int H0, H1, H2, H3, H4, H5, H6, H7, H8, H9;

    /// <summary>Creates a field element with all limbs set to zero.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Fe Zero() => default;

    /// <summary>Creates a field element representing 1.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Fe One() => new() { H0 = 1 };

    /// <summary>
    /// h = f + g
    /// Preconditions: |f|,|g| bounded by 1.1*2^25,1.1*2^24,...
    /// Postconditions: |h| bounded by 1.1*2^26,1.1*2^25,...
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Add(out Fe h, in Fe f, in Fe g)
    {
        h.H0 = f.H0 + g.H0;
        h.H1 = f.H1 + g.H1;
        h.H2 = f.H2 + g.H2;
        h.H3 = f.H3 + g.H3;
        h.H4 = f.H4 + g.H4;
        h.H5 = f.H5 + g.H5;
        h.H6 = f.H6 + g.H6;
        h.H7 = f.H7 + g.H7;
        h.H8 = f.H8 + g.H8;
        h.H9 = f.H9 + g.H9;
    }

    /// <summary>
    /// h = f - g
    /// Preconditions: |f|,|g| bounded by 1.1*2^25,1.1*2^24,...
    /// Postconditions: |h| bounded by 1.1*2^26,1.1*2^25,...
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Sub(out Fe h, in Fe f, in Fe g)
    {
        h.H0 = f.H0 - g.H0;
        h.H1 = f.H1 - g.H1;
        h.H2 = f.H2 - g.H2;
        h.H3 = f.H3 - g.H3;
        h.H4 = f.H4 - g.H4;
        h.H5 = f.H5 - g.H5;
        h.H6 = f.H6 - g.H6;
        h.H7 = f.H7 - g.H7;
        h.H8 = f.H8 - g.H8;
        h.H9 = f.H9 - g.H9;
    }

    /// <summary>
    /// h = -f
    /// Preconditions: |f| bounded by 1.1*2^25,1.1*2^24,...
    /// Postconditions: |h| bounded by 1.1*2^25,1.1*2^24,...
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Neg(out Fe h, in Fe f)
    {
        h.H0 = -f.H0;
        h.H1 = -f.H1;
        h.H2 = -f.H2;
        h.H3 = -f.H3;
        h.H4 = -f.H4;
        h.H5 = -f.H5;
        h.H6 = -f.H6;
        h.H7 = -f.H7;
        h.H8 = -f.H8;
        h.H9 = -f.H9;
    }

    /// <summary>
    /// Conditional move: if b == 1, replace f with g; if b == 0, leave f unchanged.
    /// Preconditions: b in {0,1}
    /// This is constant-time.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void CMov(ref Fe f, in Fe g, int b)
    {
        int mask = -b; // 0 or 0xFFFFFFFF
        f.H0 ^= (f.H0 ^ g.H0) & mask;
        f.H1 ^= (f.H1 ^ g.H1) & mask;
        f.H2 ^= (f.H2 ^ g.H2) & mask;
        f.H3 ^= (f.H3 ^ g.H3) & mask;
        f.H4 ^= (f.H4 ^ g.H4) & mask;
        f.H5 ^= (f.H5 ^ g.H5) & mask;
        f.H6 ^= (f.H6 ^ g.H6) & mask;
        f.H7 ^= (f.H7 ^ g.H7) & mask;
        f.H8 ^= (f.H8 ^ g.H8) & mask;
        f.H9 ^= (f.H9 ^ g.H9) & mask;
    }

    /// <summary>
    /// Conditional swap: if b == 1, swap f and g; if b == 0, leave unchanged.
    /// Preconditions: b in {0,1}
    /// This is constant-time.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void CSwap(ref Fe f, ref Fe g, int b)
    {
        int mask = -b;
        int x0 = (f.H0 ^ g.H0) & mask;
        int x1 = (f.H1 ^ g.H1) & mask;
        int x2 = (f.H2 ^ g.H2) & mask;
        int x3 = (f.H3 ^ g.H3) & mask;
        int x4 = (f.H4 ^ g.H4) & mask;
        int x5 = (f.H5 ^ g.H5) & mask;
        int x6 = (f.H6 ^ g.H6) & mask;
        int x7 = (f.H7 ^ g.H7) & mask;
        int x8 = (f.H8 ^ g.H8) & mask;
        int x9 = (f.H9 ^ g.H9) & mask;
        f.H0 ^= x0; g.H0 ^= x0;
        f.H1 ^= x1; g.H1 ^= x1;
        f.H2 ^= x2; g.H2 ^= x2;
        f.H3 ^= x3; g.H3 ^= x3;
        f.H4 ^= x4; g.H4 ^= x4;
        f.H5 ^= x5; g.H5 ^= x5;
        f.H6 ^= x6; g.H6 ^= x6;
        f.H7 ^= x7; g.H7 ^= x7;
        f.H8 ^= x8; g.H8 ^= x8;
        f.H9 ^= x9; g.H9 ^= x9;
    }

    /// <summary>
    /// Load a 32-byte little-endian representation into a field element.
    /// Ignores the top bit of byte 31 (the 256th bit).
    /// </summary>
    public static void FromBytes(out Fe h, ReadOnlySpan<byte> s)
    {
        long h0 = Load4(s);
        long h1 = Load3(s[4..]) << 6;
        long h2 = Load3(s[7..]) << 5;
        long h3 = Load3(s[10..]) << 3;
        long h4 = Load3(s[13..]) << 2;
        long h5 = Load4(s[16..]);
        long h6 = Load3(s[20..]) << 7;
        long h7 = Load3(s[23..]) << 5;
        long h8 = Load3(s[26..]) << 4;
        long h9 = (Load3(s[29..]) & 0x7FFFFF) << 2; // mask = 8388607

        // Carry chain to reduce to canonical form
        long carry9 = (h9 + (1L << 24)) >> 25; h0 += carry9 * 19; h9 -= carry9 << 25;
        long carry1 = (h1 + (1L << 24)) >> 25; h2 += carry1; h1 -= carry1 << 25;
        long carry3 = (h3 + (1L << 24)) >> 25; h4 += carry3; h3 -= carry3 << 25;
        long carry5 = (h5 + (1L << 24)) >> 25; h6 += carry5; h5 -= carry5 << 25;
        long carry7 = (h7 + (1L << 24)) >> 25; h8 += carry7; h7 -= carry7 << 25;

        long carry0 = (h0 + (1L << 25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
        long carry2 = (h2 + (1L << 25)) >> 26; h3 += carry2; h2 -= carry2 << 26;
        long carry4 = (h4 + (1L << 25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
        long carry6 = (h6 + (1L << 25)) >> 26; h7 += carry6; h6 -= carry6 << 26;
        long carry8 = (h8 + (1L << 25)) >> 26; h9 += carry8; h8 -= carry8 << 26;

        h.H0 = (int)h0;
        h.H1 = (int)h1;
        h.H2 = (int)h2;
        h.H3 = (int)h3;
        h.H4 = (int)h4;
        h.H5 = (int)h5;
        h.H6 = (int)h6;
        h.H7 = (int)h7;
        h.H8 = (int)h8;
        h.H9 = (int)h9;
    }

    /// <summary>
    /// Store a field element as 32 bytes in little-endian format.
    /// Reduces modulo 2^255-19 first.
    /// </summary>
    public static void ToBytes(Span<byte> s, in Fe h)
    {
        int h0 = h.H0, h1 = h.H1, h2 = h.H2, h3 = h.H3, h4 = h.H4;
        int h5 = h.H5, h6 = h.H6, h7 = h.H7, h8 = h.H8, h9 = h.H9;

        // Compute q = floor(h / (2^255 - 19))
        int q = (19 * h9 + (1 << 24)) >> 25;
        q = (h0 + q) >> 26;
        q = (h1 + q) >> 25;
        q = (h2 + q) >> 26;
        q = (h3 + q) >> 25;
        q = (h4 + q) >> 26;
        q = (h5 + q) >> 25;
        q = (h6 + q) >> 26;
        q = (h7 + q) >> 25;
        q = (h8 + q) >> 26;
        q = (h9 + q) >> 25;

        // h -= q * (2^255 - 19) = h + 19*q - q*2^255
        // Since q*2^255 only affects the top, we just add 19*q to h0
        h0 += 19 * q;

        // Carry chain
        int carry0 = h0 >> 26; h1 += carry0; h0 -= carry0 << 26;
        int carry1 = h1 >> 25; h2 += carry1; h1 -= carry1 << 25;
        int carry2 = h2 >> 26; h3 += carry2; h2 -= carry2 << 26;
        int carry3 = h3 >> 25; h4 += carry3; h3 -= carry3 << 25;
        int carry4 = h4 >> 26; h5 += carry4; h4 -= carry4 << 26;
        int carry5 = h5 >> 25; h6 += carry5; h5 -= carry5 << 25;
        int carry6 = h6 >> 26; h7 += carry6; h6 -= carry6 << 26;
        int carry7 = h7 >> 25; h8 += carry7; h7 -= carry7 << 25;
        int carry8 = h8 >> 26; h9 += carry8; h8 -= carry8 << 26;
        int carry9 = h9 >> 25; h9 -= carry9 << 25;

        // Pack into bytes
        s[0] = (byte)(h0);
        s[1] = (byte)(h0 >> 8);
        s[2] = (byte)(h0 >> 16);
        s[3] = (byte)((h0 >> 24) | (h1 << 2));
        s[4] = (byte)(h1 >> 6);
        s[5] = (byte)(h1 >> 14);
        s[6] = (byte)((h1 >> 22) | (h2 << 3));
        s[7] = (byte)(h2 >> 5);
        s[8] = (byte)(h2 >> 13);
        s[9] = (byte)((h2 >> 21) | (h3 << 5));
        s[10] = (byte)(h3 >> 3);
        s[11] = (byte)(h3 >> 11);
        s[12] = (byte)((h3 >> 19) | (h4 << 6));
        s[13] = (byte)(h4 >> 2);
        s[14] = (byte)(h4 >> 10);
        s[15] = (byte)(h4 >> 18);
        s[16] = (byte)(h5);
        s[17] = (byte)(h5 >> 8);
        s[18] = (byte)(h5 >> 16);
        s[19] = (byte)((h5 >> 24) | (h6 << 1));
        s[20] = (byte)(h6 >> 7);
        s[21] = (byte)(h6 >> 15);
        s[22] = (byte)((h6 >> 23) | (h7 << 3));
        s[23] = (byte)(h7 >> 5);
        s[24] = (byte)(h7 >> 13);
        s[25] = (byte)((h7 >> 21) | (h8 << 4));
        s[26] = (byte)(h8 >> 4);
        s[27] = (byte)(h8 >> 12);
        s[28] = (byte)((h8 >> 20) | (h9 << 6));
        s[29] = (byte)(h9 >> 2);
        s[30] = (byte)(h9 >> 10);
        s[31] = (byte)(h9 >> 18);
    }

    /// <summary>
    /// h = f * g
    /// Schoolbook multiplication with reduction modulo 2^255-19.
    /// Preconditions: |f|,|g| bounded by 1.65*2^26,1.65*2^25,...
    /// Postconditions: |h| bounded by 1.01*2^25,1.01*2^24,...
    /// </summary>
    public static void Mul(out Fe h, in Fe f, in Fe g)
    {
        int f0 = f.H0, f1 = f.H1, f2 = f.H2, f3 = f.H3, f4 = f.H4;
        int f5 = f.H5, f6 = f.H6, f7 = f.H7, f8 = f.H8, f9 = f.H9;
        int g0 = g.H0, g1 = g.H1, g2 = g.H2, g3 = g.H3, g4 = g.H4;
        int g5 = g.H5, g6 = g.H6, g7 = g.H7, g8 = g.H8, g9 = g.H9;

        // Precompute 19*g_i for reduction (2^255 ≡ 19 mod p)
        int g1_19 = 19 * g1;
        int g2_19 = 19 * g2;
        int g3_19 = 19 * g3;
        int g4_19 = 19 * g4;
        int g5_19 = 19 * g5;
        int g6_19 = 19 * g6;
        int g7_19 = 19 * g7;
        int g8_19 = 19 * g8;
        int g9_19 = 19 * g9;

        // Precompute 2*f_i for odd indices
        int f1_2 = 2 * f1;
        int f3_2 = 2 * f3;
        int f5_2 = 2 * f5;
        int f7_2 = 2 * f7;
        int f9_2 = 2 * f9;

        // Schoolbook multiplication with 64-bit intermediates
        long f0g0 = f0 * (long)g0;
        long f0g1 = f0 * (long)g1;
        long f0g2 = f0 * (long)g2;
        long f0g3 = f0 * (long)g3;
        long f0g4 = f0 * (long)g4;
        long f0g5 = f0 * (long)g5;
        long f0g6 = f0 * (long)g6;
        long f0g7 = f0 * (long)g7;
        long f0g8 = f0 * (long)g8;
        long f0g9 = f0 * (long)g9;
        long f1g0 = f1 * (long)g0;
        long f1g1_2 = f1_2 * (long)g1;
        long f1g2 = f1 * (long)g2;
        long f1g3_2 = f1_2 * (long)g3;
        long f1g4 = f1 * (long)g4;
        long f1g5_2 = f1_2 * (long)g5;
        long f1g6 = f1 * (long)g6;
        long f1g7_2 = f1_2 * (long)g7;
        long f1g8 = f1 * (long)g8;
        long f1g9_38 = f1_2 * (long)g9_19;
        long f2g0 = f2 * (long)g0;
        long f2g1 = f2 * (long)g1;
        long f2g2 = f2 * (long)g2;
        long f2g3 = f2 * (long)g3;
        long f2g4 = f2 * (long)g4;
        long f2g5 = f2 * (long)g5;
        long f2g6 = f2 * (long)g6;
        long f2g7 = f2 * (long)g7;
        long f2g8_19 = f2 * (long)g8_19;
        long f2g9_19 = f2 * (long)g9_19;
        long f3g0 = f3 * (long)g0;
        long f3g1_2 = f3_2 * (long)g1;
        long f3g2 = f3 * (long)g2;
        long f3g3_2 = f3_2 * (long)g3;
        long f3g4 = f3 * (long)g4;
        long f3g5_2 = f3_2 * (long)g5;
        long f3g6 = f3 * (long)g6;
        long f3g7_38 = f3_2 * (long)g7_19;
        long f3g8_19 = f3 * (long)g8_19;
        long f3g9_38 = f3_2 * (long)g9_19;
        long f4g0 = f4 * (long)g0;
        long f4g1 = f4 * (long)g1;
        long f4g2 = f4 * (long)g2;
        long f4g3 = f4 * (long)g3;
        long f4g4 = f4 * (long)g4;
        long f4g5 = f4 * (long)g5;
        long f4g6_19 = f4 * (long)g6_19;
        long f4g7_19 = f4 * (long)g7_19;
        long f4g8_19 = f4 * (long)g8_19;
        long f4g9_19 = f4 * (long)g9_19;
        long f5g0 = f5 * (long)g0;
        long f5g1_2 = f5_2 * (long)g1;
        long f5g2 = f5 * (long)g2;
        long f5g3_2 = f5_2 * (long)g3;
        long f5g4 = f5 * (long)g4;
        long f5g5_38 = f5_2 * (long)g5_19;
        long f5g6_19 = f5 * (long)g6_19;
        long f5g7_38 = f5_2 * (long)g7_19;
        long f5g8_19 = f5 * (long)g8_19;
        long f5g9_38 = f5_2 * (long)g9_19;
        long f6g0 = f6 * (long)g0;
        long f6g1 = f6 * (long)g1;
        long f6g2 = f6 * (long)g2;
        long f6g3 = f6 * (long)g3;
        long f6g4_19 = f6 * (long)g4_19;
        long f6g5_19 = f6 * (long)g5_19;
        long f6g6_19 = f6 * (long)g6_19;
        long f6g7_19 = f6 * (long)g7_19;
        long f6g8_19 = f6 * (long)g8_19;
        long f6g9_19 = f6 * (long)g9_19;
        long f7g0 = f7 * (long)g0;
        long f7g1_2 = f7_2 * (long)g1;
        long f7g2 = f7 * (long)g2;
        long f7g3_38 = f7_2 * (long)g3_19;
        long f7g4_19 = f7 * (long)g4_19;
        long f7g5_38 = f7_2 * (long)g5_19;
        long f7g6_19 = f7 * (long)g6_19;
        long f7g7_38 = f7_2 * (long)g7_19;
        long f7g8_19 = f7 * (long)g8_19;
        long f7g9_38 = f7_2 * (long)g9_19;
        long f8g0 = f8 * (long)g0;
        long f8g1 = f8 * (long)g1;
        long f8g2_19 = f8 * (long)g2_19;
        long f8g3_19 = f8 * (long)g3_19;
        long f8g4_19 = f8 * (long)g4_19;
        long f8g5_19 = f8 * (long)g5_19;
        long f8g6_19 = f8 * (long)g6_19;
        long f8g7_19 = f8 * (long)g7_19;
        long f8g8_19 = f8 * (long)g8_19;
        long f8g9_19 = f8 * (long)g9_19;
        long f9g0 = f9 * (long)g0;
        long f9g1_38 = f9_2 * (long)g1_19;
        long f9g2_19 = f9 * (long)g2_19;
        long f9g3_38 = f9_2 * (long)g3_19;
        long f9g4_19 = f9 * (long)g4_19;
        long f9g5_38 = f9_2 * (long)g5_19;
        long f9g6_19 = f9 * (long)g6_19;
        long f9g7_38 = f9_2 * (long)g7_19;
        long f9g8_19 = f9 * (long)g8_19;
        long f9g9_38 = f9_2 * (long)g9_19;

        // Sum the products
        long lh0 = f0g0 + f1g9_38 + f2g8_19 + f3g7_38 + f4g6_19 + f5g5_38 + f6g4_19 + f7g3_38 + f8g2_19 + f9g1_38;
        long lh1 = f0g1 + f1g0 + f2g9_19 + f3g8_19 + f4g7_19 + f5g6_19 + f6g5_19 + f7g4_19 + f8g3_19 + f9g2_19;
        long lh2 = f0g2 + f1g1_2 + f2g0 + f3g9_38 + f4g8_19 + f5g7_38 + f6g6_19 + f7g5_38 + f8g4_19 + f9g3_38;
        long lh3 = f0g3 + f1g2 + f2g1 + f3g0 + f4g9_19 + f5g8_19 + f6g7_19 + f7g6_19 + f8g5_19 + f9g4_19;
        long lh4 = f0g4 + f1g3_2 + f2g2 + f3g1_2 + f4g0 + f5g9_38 + f6g8_19 + f7g7_38 + f8g6_19 + f9g5_38;
        long lh5 = f0g5 + f1g4 + f2g3 + f3g2 + f4g1 + f5g0 + f6g9_19 + f7g8_19 + f8g7_19 + f9g6_19;
        long lh6 = f0g6 + f1g5_2 + f2g4 + f3g3_2 + f4g2 + f5g1_2 + f6g0 + f7g9_38 + f8g8_19 + f9g7_38;
        long lh7 = f0g7 + f1g6 + f2g5 + f3g4 + f4g3 + f5g2 + f6g1 + f7g0 + f8g9_19 + f9g8_19;
        long lh8 = f0g8 + f1g7_2 + f2g6 + f3g5_2 + f4g4 + f5g3_2 + f6g2 + f7g1_2 + f8g0 + f9g9_38;
        long lh9 = f0g9 + f1g8 + f2g7 + f3g6 + f4g5 + f5g4 + f6g3 + f7g2 + f8g1 + f9g0;

        // Carry chain
        long carry0 = (lh0 + (1L << 25)) >> 26; lh1 += carry0; lh0 -= carry0 << 26;
        long carry4 = (lh4 + (1L << 25)) >> 26; lh5 += carry4; lh4 -= carry4 << 26;
        long carry1 = (lh1 + (1L << 24)) >> 25; lh2 += carry1; lh1 -= carry1 << 25;
        long carry5 = (lh5 + (1L << 24)) >> 25; lh6 += carry5; lh5 -= carry5 << 25;
        long carry2 = (lh2 + (1L << 25)) >> 26; lh3 += carry2; lh2 -= carry2 << 26;
        long carry6 = (lh6 + (1L << 25)) >> 26; lh7 += carry6; lh6 -= carry6 << 26;
        long carry3 = (lh3 + (1L << 24)) >> 25; lh4 += carry3; lh3 -= carry3 << 25;
        long carry7 = (lh7 + (1L << 24)) >> 25; lh8 += carry7; lh7 -= carry7 << 25;
        carry4 = (lh4 + (1L << 25)) >> 26; lh5 += carry4; lh4 -= carry4 << 26;
        long carry8 = (lh8 + (1L << 25)) >> 26; lh9 += carry8; lh8 -= carry8 << 26;
        long carry9 = (lh9 + (1L << 24)) >> 25; lh0 += carry9 * 19; lh9 -= carry9 << 25;
        carry0 = (lh0 + (1L << 25)) >> 26; lh1 += carry0; lh0 -= carry0 << 26;

        h.H0 = (int)lh0;
        h.H1 = (int)lh1;
        h.H2 = (int)lh2;
        h.H3 = (int)lh3;
        h.H4 = (int)lh4;
        h.H5 = (int)lh5;
        h.H6 = (int)lh6;
        h.H7 = (int)lh7;
        h.H8 = (int)lh8;
        h.H9 = (int)lh9;
    }

    /// <summary>
    /// h = f * f (squaring, optimized)
    /// Preconditions: |f| bounded by 1.65*2^26,1.65*2^25,...
    /// Postconditions: |h| bounded by 1.01*2^25,1.01*2^24,...
    /// </summary>
    public static void Sq(out Fe h, in Fe f)
    {
        int f0 = f.H0, f1 = f.H1, f2 = f.H2, f3 = f.H3, f4 = f.H4;
        int f5 = f.H5, f6 = f.H6, f7 = f.H7, f8 = f.H8, f9 = f.H9;

        int f0_2 = 2 * f0;
        int f1_2 = 2 * f1;
        int f2_2 = 2 * f2;
        int f3_2 = 2 * f3;
        int f4_2 = 2 * f4;
        int f5_2 = 2 * f5;
        int f6_2 = 2 * f6;
        int f7_2 = 2 * f7;
        int f5_38 = 38 * f5;
        int f6_19 = 19 * f6;
        int f7_38 = 38 * f7;
        int f8_19 = 19 * f8;
        int f9_38 = 38 * f9;

        long f0f0 = f0 * (long)f0;
        long f0f1_2 = f0_2 * (long)f1;
        long f0f2_2 = f0_2 * (long)f2;
        long f0f3_2 = f0_2 * (long)f3;
        long f0f4_2 = f0_2 * (long)f4;
        long f0f5_2 = f0_2 * (long)f5;
        long f0f6_2 = f0_2 * (long)f6;
        long f0f7_2 = f0_2 * (long)f7;
        long f0f8_2 = f0_2 * (long)f8;
        long f0f9_2 = f0_2 * (long)f9;
        long f1f1_2 = f1_2 * (long)f1;
        long f1f2_2 = f1_2 * (long)f2;
        long f1f3_4 = f1_2 * (long)f3_2;
        long f1f4_2 = f1_2 * (long)f4;
        long f1f5_4 = f1_2 * (long)f5_2;
        long f1f6_2 = f1_2 * (long)f6;
        long f1f7_4 = f1_2 * (long)f7_2;
        long f1f8_2 = f1_2 * (long)f8;
        long f1f9_76 = f1_2 * (long)f9_38;
        long f2f2 = f2 * (long)f2;
        long f2f3_2 = f2_2 * (long)f3;
        long f2f4_2 = f2_2 * (long)f4;
        long f2f5_2 = f2_2 * (long)f5;
        long f2f6_2 = f2_2 * (long)f6;
        long f2f7_2 = f2_2 * (long)f7;
        long f2f8_38 = f2_2 * (long)f8_19;
        long f2f9_38 = f2 * (long)f9_38;
        long f3f3_2 = f3_2 * (long)f3;
        long f3f4_2 = f3_2 * (long)f4;
        long f3f5_4 = f3_2 * (long)f5_2;
        long f3f6_2 = f3_2 * (long)f6;
        long f3f7_76 = f3_2 * (long)f7_38;
        long f3f8_38 = f3_2 * (long)f8_19;
        long f3f9_76 = f3_2 * (long)f9_38;
        long f4f4 = f4 * (long)f4;
        long f4f5_2 = f4_2 * (long)f5;
        long f4f6_38 = f4_2 * (long)f6_19;
        long f4f7_38 = f4 * (long)f7_38;
        long f4f8_38 = f4_2 * (long)f8_19;
        long f4f9_38 = f4 * (long)f9_38;
        long f5f5_38 = f5 * (long)f5_38;
        long f5f6_38 = f5_2 * (long)f6_19;
        long f5f7_76 = f5_2 * (long)f7_38;
        long f5f8_38 = f5_2 * (long)f8_19;
        long f5f9_76 = f5_2 * (long)f9_38;
        long f6f6_19 = f6 * (long)f6_19;
        long f6f7_38 = f6 * (long)f7_38;
        long f6f8_38 = f6_2 * (long)f8_19;
        long f6f9_38 = f6 * (long)f9_38;
        long f7f7_38 = f7 * (long)f7_38;
        long f7f8_38 = f7_2 * (long)f8_19;
        long f7f9_76 = f7_2 * (long)f9_38;
        long f8f8_19 = f8 * (long)f8_19;
        long f8f9_38 = f8 * (long)f9_38;
        long f9f9_38 = f9 * (long)f9_38;

        long lh0 = f0f0 + f1f9_76 + f2f8_38 + f3f7_76 + f4f6_38 + f5f5_38;
        long lh1 = f0f1_2 + f2f9_38 + f3f8_38 + f4f7_38 + f5f6_38;
        long lh2 = f0f2_2 + f1f1_2 + f3f9_76 + f4f8_38 + f5f7_76 + f6f6_19;
        long lh3 = f0f3_2 + f1f2_2 + f4f9_38 + f5f8_38 + f6f7_38;
        long lh4 = f0f4_2 + f1f3_4 + f2f2 + f5f9_76 + f6f8_38 + f7f7_38;
        long lh5 = f0f5_2 + f1f4_2 + f2f3_2 + f6f9_38 + f7f8_38;
        long lh6 = f0f6_2 + f1f5_4 + f2f4_2 + f3f3_2 + f7f9_76 + f8f8_19;
        long lh7 = f0f7_2 + f1f6_2 + f2f5_2 + f3f4_2 + f8f9_38;
        long lh8 = f0f8_2 + f1f7_4 + f2f6_2 + f3f5_4 + f4f4 + f9f9_38;
        long lh9 = f0f9_2 + f1f8_2 + f2f7_2 + f3f6_2 + f4f5_2;

        // Carry chain
        long carry0 = (lh0 + (1L << 25)) >> 26; lh1 += carry0; lh0 -= carry0 << 26;
        long carry4 = (lh4 + (1L << 25)) >> 26; lh5 += carry4; lh4 -= carry4 << 26;
        long carry1 = (lh1 + (1L << 24)) >> 25; lh2 += carry1; lh1 -= carry1 << 25;
        long carry5 = (lh5 + (1L << 24)) >> 25; lh6 += carry5; lh5 -= carry5 << 25;
        long carry2 = (lh2 + (1L << 25)) >> 26; lh3 += carry2; lh2 -= carry2 << 26;
        long carry6 = (lh6 + (1L << 25)) >> 26; lh7 += carry6; lh6 -= carry6 << 26;
        long carry3 = (lh3 + (1L << 24)) >> 25; lh4 += carry3; lh3 -= carry3 << 25;
        long carry7 = (lh7 + (1L << 24)) >> 25; lh8 += carry7; lh7 -= carry7 << 25;
        carry4 = (lh4 + (1L << 25)) >> 26; lh5 += carry4; lh4 -= carry4 << 26;
        long carry8 = (lh8 + (1L << 25)) >> 26; lh9 += carry8; lh8 -= carry8 << 26;
        long carry9 = (lh9 + (1L << 24)) >> 25; lh0 += carry9 * 19; lh9 -= carry9 << 25;
        carry0 = (lh0 + (1L << 25)) >> 26; lh1 += carry0; lh0 -= carry0 << 26;

        h.H0 = (int)lh0;
        h.H1 = (int)lh1;
        h.H2 = (int)lh2;
        h.H3 = (int)lh3;
        h.H4 = (int)lh4;
        h.H5 = (int)lh5;
        h.H6 = (int)lh6;
        h.H7 = (int)lh7;
        h.H8 = (int)lh8;
        h.H9 = (int)lh9;
    }

    /// <summary>
    /// h = 2 * f * f (double squaring)
    /// </summary>
    public static void Sq2(out Fe h, in Fe f)
    {
        Sq(out h, in f);
        // Double all limbs and re-carry
        long lh0 = (long)h.H0 * 2;
        long lh1 = (long)h.H1 * 2;
        long lh2 = (long)h.H2 * 2;
        long lh3 = (long)h.H3 * 2;
        long lh4 = (long)h.H4 * 2;
        long lh5 = (long)h.H5 * 2;
        long lh6 = (long)h.H6 * 2;
        long lh7 = (long)h.H7 * 2;
        long lh8 = (long)h.H8 * 2;
        long lh9 = (long)h.H9 * 2;

        long carry0 = (lh0 + (1L << 25)) >> 26; lh1 += carry0; lh0 -= carry0 << 26;
        long carry4 = (lh4 + (1L << 25)) >> 26; lh5 += carry4; lh4 -= carry4 << 26;
        long carry1 = (lh1 + (1L << 24)) >> 25; lh2 += carry1; lh1 -= carry1 << 25;
        long carry5 = (lh5 + (1L << 24)) >> 25; lh6 += carry5; lh5 -= carry5 << 25;
        long carry2 = (lh2 + (1L << 25)) >> 26; lh3 += carry2; lh2 -= carry2 << 26;
        long carry6 = (lh6 + (1L << 25)) >> 26; lh7 += carry6; lh6 -= carry6 << 26;
        long carry3 = (lh3 + (1L << 24)) >> 25; lh4 += carry3; lh3 -= carry3 << 25;
        long carry7 = (lh7 + (1L << 24)) >> 25; lh8 += carry7; lh7 -= carry7 << 25;
        carry4 = (lh4 + (1L << 25)) >> 26; lh5 += carry4; lh4 -= carry4 << 26;
        long carry8 = (lh8 + (1L << 25)) >> 26; lh9 += carry8; lh8 -= carry8 << 26;
        long carry9 = (lh9 + (1L << 24)) >> 25; lh0 += carry9 * 19; lh9 -= carry9 << 25;
        carry0 = (lh0 + (1L << 25)) >> 26; lh1 += carry0; lh0 -= carry0 << 26;

        h.H0 = (int)lh0;
        h.H1 = (int)lh1;
        h.H2 = (int)lh2;
        h.H3 = (int)lh3;
        h.H4 = (int)lh4;
        h.H5 = (int)lh5;
        h.H6 = (int)lh6;
        h.H7 = (int)lh7;
        h.H8 = (int)lh8;
        h.H9 = (int)lh9;
    }

    /// <summary>
    /// out = z^(-1) = z^(2^255-21) in the field.
    /// Uses addition chain from ref10.
    /// </summary>
    public static void Invert(out Fe result, in Fe z)
    {
        Fe t0, t1, t2, t3;

        Sq(out t0, in z);
        Sq(out t1, in t0);
        Sq(out t1, in t1);
        Mul(out t1, in z, in t1);
        Mul(out t0, in t0, in t1);
        Sq(out t2, in t0);
        Mul(out t1, in t1, in t2);
        Sq(out t2, in t1);
        for (int i = 1; i < 5; i++) Sq(out t2, in t2);
        Mul(out t1, in t2, in t1);
        Sq(out t2, in t1);
        for (int i = 1; i < 10; i++) Sq(out t2, in t2);
        Mul(out t2, in t2, in t1);
        Sq(out t3, in t2);
        for (int i = 1; i < 20; i++) Sq(out t3, in t3);
        Mul(out t2, in t3, in t2);
        Sq(out t2, in t2);
        for (int i = 1; i < 10; i++) Sq(out t2, in t2);
        Mul(out t1, in t2, in t1);
        Sq(out t2, in t1);
        for (int i = 1; i < 50; i++) Sq(out t2, in t2);
        Mul(out t2, in t2, in t1);
        Sq(out t3, in t2);
        for (int i = 1; i < 100; i++) Sq(out t3, in t3);
        Mul(out t2, in t3, in t2);
        Sq(out t2, in t2);
        for (int i = 1; i < 50; i++) Sq(out t2, in t2);
        Mul(out t1, in t2, in t1);
        Sq(out t1, in t1);
        for (int i = 1; i < 5; i++) Sq(out t1, in t1);
        Mul(out result, in t1, in t0);
    }

    /// <summary>
    /// out = z^((2^255-19-2)/8) = z^(2^252-3)
    /// Used for computing square roots.
    /// </summary>
    public static void Pow22523(out Fe result, in Fe z)
    {
        Fe t0, t1, t2;

        Sq(out t0, in z);
        Sq(out t1, in t0);
        Sq(out t1, in t1);
        Mul(out t1, in z, in t1);
        Mul(out t0, in t0, in t1);
        Sq(out t0, in t0);
        Mul(out t0, in t1, in t0);
        Sq(out t1, in t0);
        for (int i = 1; i < 5; i++) Sq(out t1, in t1);
        Mul(out t0, in t1, in t0);
        Sq(out t1, in t0);
        for (int i = 1; i < 10; i++) Sq(out t1, in t1);
        Mul(out t1, in t1, in t0);
        Sq(out t2, in t1);
        for (int i = 1; i < 20; i++) Sq(out t2, in t2);
        Mul(out t1, in t2, in t1);
        Sq(out t1, in t1);
        for (int i = 1; i < 10; i++) Sq(out t1, in t1);
        Mul(out t0, in t1, in t0);
        Sq(out t1, in t0);
        for (int i = 1; i < 50; i++) Sq(out t1, in t1);
        Mul(out t1, in t1, in t0);
        Sq(out t2, in t1);
        for (int i = 1; i < 100; i++) Sq(out t2, in t2);
        Mul(out t1, in t2, in t1);
        Sq(out t1, in t1);
        for (int i = 1; i < 50; i++) Sq(out t1, in t1);
        Mul(out t0, in t1, in t0);
        Sq(out t0, in t0);
        Sq(out t0, in t0);
        Mul(out result, in t0, in z);
    }

    /// <summary>
    /// Returns 1 if f is negative (i.e., the low bit of the canonical representation is 1).
    /// Returns 0 otherwise.
    /// </summary>
    public static int IsNegative(in Fe f)
    {
        Span<byte> s = stackalloc byte[32];
        ToBytes(s, in f);
        return s[0] & 1;
    }

    /// <summary>
    /// Returns 1 if f is non-zero, 0 if f is zero.
    /// </summary>
    public static int IsNonZero(in Fe f)
    {
        Span<byte> s = stackalloc byte[32];
        ToBytes(s, in f);
        byte r = 0;
        for (int i = 0; i < 32; i++) r |= s[i];
        // Constant-time conversion to 0 or 1
        r |= (byte)(r >> 4);
        r |= (byte)(r >> 2);
        r |= (byte)(r >> 1);
        return r & 1;
    }

    /// <summary>Copy f to h.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Copy(out Fe h, in Fe f) => h = f;

    // Helper: load 3 bytes as little-endian uint64
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static long Load3(ReadOnlySpan<byte> s)
    {
        return s[0] | ((long)s[1] << 8) | ((long)s[2] << 16);
    }

    // Helper: load 4 bytes as little-endian uint64
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static long Load4(ReadOnlySpan<byte> s)
    {
        return s[0] | ((long)s[1] << 8) | ((long)s[2] << 16) | ((long)s[3] << 24);
    }
}

