// SPDX-License-Identifier: BSD-3-Clause
// SPDX-FileCopyrightText: Z-Wave Alliance <https://z-wavealliance.org>
using System;
using System.Security.Cryptography;

namespace ZWave.Security
{
    /// <summary>
    /// Managed implementation of the S2 crypto primitives otherwise taken from the native
    /// s2crypto library (libs2). It is used where no native library exists for the process
    /// architecture, e.g. macOS on Apple Silicon, where only an x86_64 build is available.
    ///
    /// The functions have the same signatures and results as their native counterparts in
    /// <see cref="SecurityS2Utils"/>; the unit tests compare them with vectors produced by the
    /// native library.
    ///
    /// AES-CCM (M = 8, L = 2), AES-CMAC (RFC 4493), the CKDF key derivations of the S2
    /// specification, AES-128 CTR_DRBG without derivation function (NIST SP 800-90A) and
    /// X25519 (RFC 7748, ported from TweetNaCl).
    /// </summary>
    internal static class SecurityS2Managed
    {
        private const int BLOCK = 16;
        private const int CCM_TAG_SIZE = 8;   // M
        private const int CCM_NONCE_SIZE = 13; // 15 - L, with L = 2

        #region AES

        private static ICryptoTransform CreateEncryptor(byte[] key)
        {
            using (var aes = Aes.Create())
            {
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;
                aes.KeySize = 128;
                return aes.CreateEncryptor(key, null);
            }
        }

        private static void EncryptBlock(ICryptoTransform aes, byte[] input, int inputOffset, byte[] output, int outputOffset)
        {
            aes.TransformBlock(input, inputOffset, BLOCK, output, outputOffset);
        }

        public static void Aes128EcbEncrypt(byte[] input, byte[] key, byte[] output)
        {
            using (var aes = CreateEncryptor(Key16(key)))
            {
                var block = new byte[BLOCK];
                Array.Copy(input, block, BLOCK);
                EncryptBlock(aes, block, 0, output, 0);
            }
        }

        private static byte[] Key16(byte[] key)
        {
            if (key.Length == BLOCK)
                return key;
            var ret = new byte[BLOCK];
            Array.Copy(key, ret, BLOCK);
            return ret;
        }

        #endregion

        #region CMAC

        internal static byte[] Cmac(byte[] key, byte[] message)
        {
            using (var aes = CreateEncryptor(Key16(key)))
            {
                var l = new byte[BLOCK];
                EncryptBlock(aes, new byte[BLOCK], 0, l, 0);
                var k1 = ShiftLeftXor(l);
                var k2 = ShiftLeftXor(k1);

                int n = (message.Length + BLOCK - 1) / BLOCK;
                bool complete = message.Length > 0 && message.Length % BLOCK == 0;
                if (n == 0)
                    n = 1;

                var last = new byte[BLOCK];
                int lastOffset = (n - 1) * BLOCK;
                if (complete)
                {
                    for (int i = 0; i < BLOCK; i++)
                        last[i] = (byte)(message[lastOffset + i] ^ k1[i]);
                }
                else
                {
                    int rem = message.Length - lastOffset;
                    for (int i = 0; i < rem; i++)
                        last[i] = message[lastOffset + i];
                    last[rem] = 0x80;
                    for (int i = 0; i < BLOCK; i++)
                        last[i] ^= k2[i];
                }

                var x = new byte[BLOCK];
                var y = new byte[BLOCK];
                for (int b = 0; b < n - 1; b++)
                {
                    for (int i = 0; i < BLOCK; i++)
                        y[i] = (byte)(x[i] ^ message[b * BLOCK + i]);
                    EncryptBlock(aes, y, 0, x, 0);
                }
                for (int i = 0; i < BLOCK; i++)
                    y[i] = (byte)(x[i] ^ last[i]);
                EncryptBlock(aes, y, 0, x, 0);
                return x;
            }
        }

        private static byte[] ShiftLeftXor(byte[] input)
        {
            var ret = new byte[BLOCK];
            for (int i = 0; i < BLOCK - 1; i++)
                ret[i] = (byte)((input[i] << 1) | (input[i + 1] >> 7));
            ret[BLOCK - 1] = (byte)(input[BLOCK - 1] << 1);
            if ((input[0] & 0x80) != 0)
                ret[BLOCK - 1] ^= 0x87;
            return ret;
        }

        #endregion

        #region CCM

        /// <returns>Length of ciphertext and tag written to <paramref name="buffer"/>.</returns>
        public static uint CcmEncryptAndAuth(byte[] key, byte[] nonce, byte[] aad, uint aadLen, byte[] buffer, ushort plaintextLen)
        {
            using (var aes = CreateEncryptor(Key16(key)))
            {
                var tag = CcmMac(aes, nonce, aad, (int)aadLen, buffer, plaintextLen);
                CcmCtr(aes, nonce, buffer, plaintextLen, tag);
                Array.Copy(tag, 0, buffer, plaintextLen, CCM_TAG_SIZE);
                return (uint)(plaintextLen + CCM_TAG_SIZE);
            }
        }

        /// <returns>Length of the plaintext written to <paramref name="buffer"/>, 0 when authentication fails.</returns>
        public static ushort CcmDecryptAndAuth(byte[] key, byte[] nonce, byte[] aad, uint aadLen, byte[] buffer, uint ciphertextLen)
        {
            if (ciphertextLen < CCM_TAG_SIZE || ciphertextLen > buffer.Length)
                return 0;
            int plaintextLen = (int)ciphertextLen - CCM_TAG_SIZE;
            using (var aes = CreateEncryptor(Key16(key)))
            {
                var receivedTag = new byte[CCM_TAG_SIZE];
                Array.Copy(buffer, plaintextLen, receivedTag, 0, CCM_TAG_SIZE);
                CcmCtr(aes, nonce, buffer, plaintextLen, receivedTag);
                var tag = CcmMac(aes, nonce, aad, (int)aadLen, buffer, plaintextLen);

                int diff = 0;
                for (int i = 0; i < CCM_TAG_SIZE; i++)
                    diff |= tag[i] ^ receivedTag[i];
                if (diff != 0)
                {
                    Array.Clear(buffer, 0, plaintextLen);
                    return 0;
                }
                return (ushort)plaintextLen;
            }
        }

        // CBC-MAC over B0 | encoded AAD | plaintext; returns the first M bytes.
        private static byte[] CcmMac(ICryptoTransform aes, byte[] nonce, byte[] aad, int aadLen, byte[] text, int textLen)
        {
            var x = new byte[BLOCK];
            var y = new byte[BLOCK];

            var b0 = new byte[BLOCK];
            b0[0] = (byte)((aadLen > 0 ? 0x40 : 0) | (((CCM_TAG_SIZE - 2) / 2) << 3) | (2 - 1));
            Array.Copy(nonce, 0, b0, 1, CCM_NONCE_SIZE);
            b0[14] = (byte)(textLen >> 8);
            b0[15] = (byte)textLen;
            EncryptBlock(aes, b0, 0, x, 0);

            if (aadLen > 0)
            {
                // AAD lengths below 0xFF00 are encoded in two bytes; S2 AAD is always shorter.
                var encoded = new byte[2 + aadLen];
                encoded[0] = (byte)(aadLen >> 8);
                encoded[1] = (byte)aadLen;
                Array.Copy(aad, 0, encoded, 2, aadLen);
                CbcMacUpdate(aes, x, y, encoded, encoded.Length);
            }
            CbcMacUpdate(aes, x, y, text, textLen);

            var tag = new byte[CCM_TAG_SIZE];
            Array.Copy(x, tag, CCM_TAG_SIZE);
            return tag;
        }

        // Zero padded CBC-MAC over data, continuing from state x.
        private static void CbcMacUpdate(ICryptoTransform aes, byte[] x, byte[] y, byte[] data, int length)
        {
            for (int offset = 0; offset < length; offset += BLOCK)
            {
                int n = Math.Min(BLOCK, length - offset);
                for (int i = 0; i < BLOCK; i++)
                    y[i] = (byte)(x[i] ^ (i < n ? data[offset + i] : 0));
                EncryptBlock(aes, y, 0, x, 0);
            }
        }

        // CTR mode: data ^= S1.., tag ^= S0.
        private static void CcmCtr(ICryptoTransform aes, byte[] nonce, byte[] data, int length, byte[] tag)
        {
            var a = new byte[BLOCK];
            var s = new byte[BLOCK];
            a[0] = 2 - 1;
            Array.Copy(nonce, 0, a, 1, CCM_NONCE_SIZE);

            EncryptBlock(aes, a, 0, s, 0);
            for (int i = 0; i < CCM_TAG_SIZE; i++)
                tag[i] ^= s[i];

            ushort counter = 1;
            for (int offset = 0; offset < length; offset += BLOCK, counter++)
            {
                a[14] = (byte)(counter >> 8);
                a[15] = (byte)counter;
                EncryptBlock(aes, a, 0, s, 0);
                int n = Math.Min(BLOCK, length - offset);
                for (int i = 0; i < n; i++)
                    data[offset + i] ^= s[i];
            }
        }

        #endregion

        #region Key derivation (CKDF)

        private static byte[] Repeat(byte value, int count)
        {
            var ret = new byte[count];
            for (int i = 0; i < count; i++)
                ret[i] = value;
            return ret;
        }

        private static byte[] Concat(params byte[][] parts)
        {
            int len = 0;
            foreach (var p in parts)
                len += p.Length;
            var ret = new byte[len];
            int offset = 0;
            foreach (var p in parts)
            {
                Array.Copy(p, 0, ret, offset, p.Length);
                offset += p.Length;
            }
            return ret;
        }

        // T(i) = CMAC(key, T(i-1) | constant | i), T(0) empty; returns T1..T4.
        private static byte[][] Expand(byte[] key, byte constantByte)
        {
            var constant = Repeat(constantByte, 15);
            var t = new byte[0];
            var ret = new byte[4][];
            for (int i = 0; i < 4; i++)
            {
                t = Cmac(key, Concat(t, constant, new[] { (byte)(i + 1) }));
                ret[i] = t;
            }
            return ret;
        }

        private static void WriteExpanded(byte[][] t, byte[] ccmKey, byte[] noncePersonalization, byte[] mpanKey)
        {
            Array.Copy(t[0], 0, ccmKey, 0, BLOCK);
            Array.Copy(t[1], 0, noncePersonalization, 0, BLOCK);
            Array.Copy(t[2], 0, noncePersonalization, BLOCK, BLOCK);
            Array.Copy(t[3], 0, mpanKey, 0, BLOCK);
        }

        public static void NetworkKeyExpand(byte[] networkKey, byte[] ccmKey, byte[] noncePersonalization, byte[] mpanKey)
        {
            WriteExpanded(Expand(networkKey, 0x55), ccmKey, noncePersonalization, mpanKey);
        }

        public static void TempKeyExpand(byte[] prk, byte[] ccmKey, byte[] noncePersonalization, byte[] mpanKey)
        {
            WriteExpanded(Expand(prk, 0x88), ccmKey, noncePersonalization, mpanKey);
        }

        /// <param name="authTag">ECDH public key of the controller | ECDH public key of the device (64 bytes).</param>
        public static void TempKeyExtract(byte[] sharedSecret, byte[] authTag, byte[] prk)
        {
            var mac = Cmac(Repeat(0x33, BLOCK), Concat(Slice(sharedSecret, 32), Slice(authTag, 64)));
            Array.Copy(mac, prk, BLOCK);
        }

        private static byte[] Slice(byte[] data, int length)
        {
            var ret = new byte[length];
            Array.Copy(data, ret, length);
            return ret;
        }

        #endregion

        #region CTR_DRBG and NextNonce

        public static void AesCtrDrbgInstantiate(ref CTR_DRBG_CTX ctx, byte[] entropy, byte[] personalization)
        {
            // Like libs2, the personalization is XORed into the caller's entropy buffer in place.
            for (int i = 0; i < 2 * BLOCK; i++)
                entropy[i] ^= personalization != null ? personalization[i] : (byte)0;
            var seed = new byte[2 * BLOCK];
            Array.Copy(entropy, seed, seed.Length);

            var k = new byte[BLOCK];
            var v = new byte[BLOCK];
            DrbgUpdate(seed, k, v);
            ctx = new CTR_DRBG_CTX(0, v, k);
        }

        public static int AesCtrDrbgGenerate(ref CTR_DRBG_CTX ctx, byte[] output)
        {
            var k = ctx.K;
            var v = ctx.V;
            Increment(v);
            using (var aes = CreateEncryptor(k))
            {
                var block = new byte[BLOCK];
                EncryptBlock(aes, v, 0, block, 0);
                Array.Copy(block, output, Math.Min(BLOCK, output.Length));
            }
            DrbgUpdate(new byte[2 * BLOCK], k, v);
            ctx = new CTR_DRBG_CTX(ctx.Df, v, k);
            return 1;
        }

        // CTR_DRBG_Update with seedlen = 32: (K, V) = (K, V) encrypted counter blocks ^ provided data.
        private static void DrbgUpdate(byte[] provided, byte[] k, byte[] v)
        {
            var temp = new byte[2 * BLOCK];
            using (var aes = CreateEncryptor(k))
            {
                for (int i = 0; i < 2; i++)
                {
                    Increment(v);
                    EncryptBlock(aes, v, 0, temp, i * BLOCK);
                }
            }
            for (int i = 0; i < temp.Length; i++)
                temp[i] ^= provided[i];
            Array.Copy(temp, 0, k, 0, BLOCK);
            Array.Copy(temp, BLOCK, v, 0, BLOCK);
        }

        private static void Increment(byte[] v)
        {
            for (int i = BLOCK - 1; i >= 0; i--)
            {
                if (++v[i] != 0)
                    break;
            }
        }

        /// <summary>
        /// Instantiates the SPAN: MEI = CKDF-MEI(sender EI, receiver EI) seeds a CTR_DRBG
        /// personalized with the nonce personalization string of the key.
        /// </summary>
        public static void NextNonceInstantiate(ref CTR_DRBG_CTX ctx, byte[] eiSender, byte[] eiReceiver, byte[] personalization)
        {
            // CKDF-MEI-Extract
            var noncePrk = Cmac(Repeat(0x26, BLOCK), Concat(Slice(eiSender, BLOCK), Slice(eiReceiver, BLOCK)));
            // CKDF-MEI-Expand: T0 = ConstantEI | 0x00, T(i) = CMAC(NoncePRK, T(i-1) | ConstantEI | i)
            var constantEi = Repeat(0x88, 15);
            var t0 = Concat(constantEi, new byte[] { 0x00 });
            var t1 = Cmac(noncePrk, Concat(t0, constantEi, new byte[] { 0x01 }));
            var t2 = Cmac(noncePrk, Concat(t1, constantEi, new byte[] { 0x02 }));
            AesCtrDrbgInstantiate(ref ctx, Concat(t1, t2), personalization);
        }

        public static int NextNonceGenerate(ref CTR_DRBG_CTX ctx, byte[] output)
        {
            AesCtrDrbgGenerate(ref ctx, output);
            return 1;
        }

        #endregion

        #region X25519 (ported from TweetNaCl, public domain)

        private static readonly long[] _121665 = { 0xDB41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        private static readonly byte[] _9 = { 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

        public static int CryptoScalarmultCurve25519Base(byte[] publicKey, byte[] privateKey)
        {
            return CryptoScalarmultCurve25519(publicKey, privateKey, _9);
        }

        public static int CryptoScalarmultCurve25519(byte[] q, byte[] n, byte[] p)
        {
            var z = new byte[32];
            Array.Copy(n, z, 31);
            z[31] = (byte)((n[31] & 127) | 64);
            z[0] &= 248;

            var x = Gf();
            Unpack25519(x, p);
            var a = Gf(); var b = Gf(); var c = Gf(); var d = Gf(); var e = Gf(); var f = Gf();
            for (int i = 0; i < 16; i++)
                b[i] = x[i];
            a[0] = d[0] = 1;

            for (int i = 254; i >= 0; --i)
            {
                int r = (z[i >> 3] >> (i & 7)) & 1;
                Sel25519(a, b, r);
                Sel25519(c, d, r);
                A(e, a, c);
                Z(a, a, c);
                A(c, b, d);
                Z(b, b, d);
                S(d, e);
                S(f, a);
                M(a, c, a);
                M(c, b, e);
                A(e, a, c);
                Z(a, a, c);
                S(b, a);
                Z(c, d, f);
                M(a, c, _121665);
                A(a, a, d);
                M(c, c, a);
                M(a, d, f);
                M(d, b, x);
                S(b, e);
                Sel25519(a, b, r);
                Sel25519(c, d, r);
            }

            Inv25519(c, c);
            M(a, a, c);
            Pack25519(q, a);
            return 0;
        }

        private static long[] Gf()
        {
            return new long[16];
        }

        private static void Car25519(long[] o)
        {
            for (int i = 0; i < 16; i++)
            {
                o[i] += 1L << 16;
                long c = o[i] >> 16;
                if (i < 15)
                    o[i + 1] += c - 1;
                else
                    o[0] += 38 * (c - 1);
                o[i] -= c << 16;
            }
        }

        private static void Sel25519(long[] p, long[] q, int b)
        {
            long c = ~(b - 1);
            for (int i = 0; i < 16; i++)
            {
                long t = c & (p[i] ^ q[i]);
                p[i] ^= t;
                q[i] ^= t;
            }
        }

        private static void Pack25519(byte[] o, long[] n)
        {
            var m = Gf();
            var t = Gf();
            for (int i = 0; i < 16; i++)
                t[i] = n[i];
            Car25519(t);
            Car25519(t);
            Car25519(t);
            for (int j = 0; j < 2; j++)
            {
                m[0] = t[0] - 0xffed;
                for (int i = 1; i < 15; i++)
                {
                    m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
                    m[i - 1] &= 0xffff;
                }
                m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
                int b = (int)((m[15] >> 16) & 1);
                m[14] &= 0xffff;
                Sel25519(t, m, 1 - b);
            }
            for (int i = 0; i < 16; i++)
            {
                o[2 * i] = (byte)(t[i] & 0xff);
                o[2 * i + 1] = (byte)(t[i] >> 8);
            }
        }

        private static void Unpack25519(long[] o, byte[] n)
        {
            for (int i = 0; i < 16; i++)
                o[i] = n[2 * i] + ((long)n[2 * i + 1] << 8);
            o[15] &= 0x7fff;
        }

        private static void A(long[] o, long[] a, long[] b)
        {
            for (int i = 0; i < 16; i++)
                o[i] = a[i] + b[i];
        }

        private static void Z(long[] o, long[] a, long[] b)
        {
            for (int i = 0; i < 16; i++)
                o[i] = a[i] - b[i];
        }

        private static void M(long[] o, long[] a, long[] b)
        {
            var t = new long[31];
            for (int i = 0; i < 16; i++)
                for (int j = 0; j < 16; j++)
                    t[i + j] += a[i] * b[j];
            for (int i = 0; i < 15; i++)
                t[i] += 38 * t[i + 16];
            for (int i = 0; i < 16; i++)
                o[i] = t[i];
            Car25519(o);
            Car25519(o);
        }

        private static void S(long[] o, long[] a)
        {
            M(o, a, a);
        }

        private static void Inv25519(long[] o, long[] input)
        {
            var c = Gf();
            for (int i = 0; i < 16; i++)
                c[i] = input[i];
            for (int a = 253; a >= 0; a--)
            {
                S(c, c);
                if (a != 2 && a != 4)
                    M(c, c, input);
            }
            for (int i = 0; i < 16; i++)
                o[i] = c[i];
        }

        #endregion
    }
}
