// SPDX-License-Identifier: BSD-3-Clause
// SPDX-FileCopyrightText: Z-Wave Alliance <https://z-wavealliance.org>
using System;
using System.Linq;
using NUnit.Framework;
using ZWave.Security;

namespace ZWaveTests.Security
{
    /// <summary>
    /// Checks the S2 crypto functions against vectors produced by the native s2crypto library
    /// (x86_64 macOS build). Each test runs on the managed implementation and on the default
    /// back end - the native library where one exists for the platform, otherwise the managed
    /// implementation again - so a difference between the two shows up on every platform with
    /// a native build.
    /// </summary>
    [TestFixture(true)]
    [TestFixture(false)]
    [NonParallelizable]
    public class SecurityS2ManagedTests
    {
        private readonly bool _forceManaged;
        private bool _saved;

        public SecurityS2ManagedTests(bool forceManaged)
        {
            _forceManaged = forceManaged;
        }

        [SetUp]
        public void SetUp()
        {
            _saved = SecurityS2Utils.UseManagedCrypto;
            if (_forceManaged)
                SecurityS2Utils.UseManagedCrypto = true;
        }

        [TearDown]
        public void TearDown()
        {
            SecurityS2Utils.UseManagedCrypto = _saved;
        }

        private static byte[] H(string hex)
        {
            var ret = new byte[hex.Length / 2];
            for (int i = 0; i < ret.Length; i++)
                ret[i] = Convert.ToByte(hex.Substring(2 * i, 2), 16);
            return ret;
        }

        private static string X(byte[] data)
        {
            return string.Concat(data.Select(b => b.ToString("X2")));
        }

        [TestCase("052A4F7499BEE3082D52779CC1E60B30", "10355A7FA4C9EE13385D82A7CCF1163B", "1B40658AAFD4F91E", "",
            "B4F24A15169BB22A")]
        [TestCase("10355A7FA4C9EE13385D82A7CCF1163B", "1B40658AAFD4F91E43688DB2D7FC2146", "264B7095BADF0429", "31",
            "EB79F972BB32075152")]
        [TestCase("264B7095BADF04294E7398BDE2072C51", "31567BA0C5EA0F34597EA3C8ED12375C", "3C6186ABD0F51A3F6489", "476C91",
            "038F32E9130F3F16E9DB77")]
        [TestCase("B5DAFF24496E93B8DD02274C7196BBE0", "C0E50A2F54799EC3E80D32577CA1C6EB", "CBF0153A5F84A9CEF3183D62",
            "D6FB20456A8FB4D9FE23486D92B7DC01",
            "06F3D33D96E53D2D4E8D5C6244ECD23EAF7FC003C5466779")]
        [TestCase("C0E50A2F54799EC3E80D32577CA1C6EB", "CBF0153A5F84A9CEF3183D6287ACD1F6", "D6FB20456A8FB4D9FE23486D92B7DC01264B7095",
            "E1062B50759ABFE4092E53789DC2E70C31",
            "61432D438382E698AE8E88A589532093B13AE97FA831D4A38A")]
        [TestCase("BDE2072C51769BC0E50A2F54799EC3E8", "C8ED12375C81A6CBF0153A5F84A9CEF3", "D3F81D42678CB1D6FB20456A8FB4D9FE23486D92B7DC01264B7095BADF04",
            "DE03284D7297BCE1062B50759ABFE4092E53789DC2E70C31567BA0C5EA0F34597EA3C8ED12375C81",
            "0FA34CA8CFA4DC46863E85447F1E7457F1BACD816C02C4FDF988D4813D9FAA7D9845E0022374098BA806C2A225DF60CE")]
        [TestCase("51769BC0E50A2F54799EC3E80D32577C", "5C81A6CBF0153A5F84A9CEF3183D6287", "678CB1D6FB20456A",
            "7297BCE1062B50759ABFE4092E53789DC2E70C31567BA0C5EA0F34597EA3C8ED12375C81A6CBF0153A5F84A9CEF3183D6287ACD1F61B40658AAFD4F91E43688DB2D7FC21466B90B5DAFF24496E93B8DD02274C7196BBE0052A4F7499BEE3082D52779CC1",
            "E9B06A51E55D35E44CFE5F3B6E21943DCA9EB2CE82023F14C8D223C5BF47E2D2ABEAB0F283753DEF9E38F75BB7C81BFA244782675EBB88B296547463A38CA83CDB3688DCDEB8EA8D5426673C56DF7B999E50D97F1EF7BBEDBC7CC44E76C3705FB52ADD5D2F2B5A4FD740B29C")]
        public void Ccm_EncryptDecrypt_MatchesNativeVectors(string key, string iv, string aad, string plaintext, string ciphertext)
        {
            var encrypted = SecurityS2Utils.CcmEncryptAndAuth(H(key), H(iv), H(aad), H(plaintext));
            Assert.AreEqual(ciphertext, X(encrypted));

            var decrypted = SecurityS2Utils.CcmDecryptAndAuth(H(key), H(iv), H(aad), H(ciphertext));
            Assert.AreEqual(plaintext, X(decrypted));

            var tampered = H(ciphertext);
            tampered[tampered.Length - 1] ^= 0x01;
            Assert.AreEqual(0, SecurityS2Utils.CcmDecryptAndAuth(H(key), H(iv), H(aad), tampered).Length);

            var wrongAad = H(aad);
            wrongAad[0] ^= 0x01;
            Assert.AreEqual(0, SecurityS2Utils.CcmDecryptAndAuth(H(key), H(iv), wrongAad, H(ciphertext)).Length);
        }

        [Test]
        public void NetworkKeyExpand_MatchesNativeVector()
        {
            byte[] ccm = new byte[16], pers = new byte[32], mpan = new byte[16];
            SecurityS2Utils.NetworkKeyExpand(H("52779CC1E60B30557A9FC4E90E33587D"), ccm, pers, mpan);
            Assert.AreEqual("98984F553E117E1E3A17F009C3FA374B", X(ccm));
            Assert.AreEqual("356898AC3F82620D510798E666EF101EF8D0D97AB15D0D9F5327AE757A7FAE3C", X(pers));
            Assert.AreEqual("905E5C96F619FD583091620572DF0E9B", X(mpan));
        }

        [Test]
        public void TempKeyExtractAndExpand_MatchesNativeVector()
        {
            var prk = new byte[16];
            SecurityS2Utils.TempKeyExtract(
                H("5D82A7CCF1163B6085AACFF4193E6388ADD2F71C41668BB0D5FA1F44698EB3D8"),
                H("688DB2D7FC21466B90B5DAFF24496E93B8DD02274C7196BBE0052A4F7499BEE3082D52779CC1E60B30557A9FC4E90E33587DA2C7EC11365B80A5CAEF14395E83"),
                prk);
            Assert.AreEqual("8D22B26ECB58126878240B8235787E50", X(prk));

            byte[] ccm = new byte[16], pers = new byte[32], mpan = new byte[16];
            SecurityS2Utils.TempKeyExpand(prk, ccm, pers, mpan);
            Assert.AreEqual("8F967C723C2AF2A3A37D0F9FFEF8BF41", X(ccm));
            Assert.AreEqual("7E781AD7DCCE490E4CC605CD24B12C6D3FCD3CED10A59800EEC06102DB15C71F", X(pers));
            Assert.AreEqual("A54943EFBD9A957E469FDA08B122B418", X(mpan));
        }

        [TestCase("7398BDE2072C51769BC0E50A2F54799EC3E80D32577CA1C6EB10355A7FA4C9EE",
            "99BEE3082D52779CC1E60B30557A9FC4E90E33587DA2C7EC11365B80A5CAEF14",
            "48FFC64C604B04BB38C50C72E1FCB967E31045B0B5E08EEBC0B705005DE86338",
            "3CAA24EAA64E006FC266DF4C45A6165E7FA707A94D38980BA89847D04EF2591D",
            "9616667659546F49944AB081E3008ECFA50DC5C32B25CC275BC9229C5F625921")]
        [TestCase("7EA3C8ED12375C81A6CBF0153A5F84A9CEF3183D6287ACD1F61B40658AAFD4F9",
            "A4C9EE13385D82A7CCF1163B6085AACFF4193E6388ADD2F71C41668BB0D5FA1F",
            "B90548B38DA92C81020C7F5C26F4D85BE03F1903E0DFFDB5B879466999620474",
            "1528C60441EAA0466C6B07414F3A53CFEC457F8FFD474E13D37180CDC5FF440C",
            "AF1728109899DFCAD9213355B64434AAA1F74E9E4FFF51725E8AC4AE92DD4B12")]
        // RFC 7748, section 6.1
        [TestCase("77076D0A7318A57D3C16C17251B26645DF4C2F87EBC0992AB177FBA51DB92C2A",
            "5DAB087E624A8A4B79E17F8B83800EE66F3BB1292618B6FD1C2F8B27FF88E0EB",
            "8520F0098930A754748B7DDCB43EF75A0DBF3A0D26381AF4EBA4A98EAA9B4E6A",
            "DE9EDB7D7B7DC1B4D35B61C2ECE435373F8343C85B78674DADFC7E146F882B4F",
            "4A5D9D5BA4CE2DE1728E3BF480350F25E07E21C947D19E3376F09B3C1E161742")]
        public void Curve25519_MatchesVectors(string privateA, string privateB, string publicA, string publicB, string shared)
        {
            var pa = new byte[32];
            var pb = new byte[32];
            Assert.AreEqual(0, SecurityS2Utils.CryptoScalarmultCurve25519Base(pa, H(privateA)));
            Assert.AreEqual(0, SecurityS2Utils.CryptoScalarmultCurve25519Base(pb, H(privateB)));
            Assert.AreEqual(publicA, X(pa));
            Assert.AreEqual(publicB, X(pb));

            var s1 = new byte[32];
            var s2 = new byte[32];
            Assert.AreEqual(0, SecurityS2Utils.CryptoScalarmultCurve25519(s1, H(privateA), pb));
            Assert.AreEqual(0, SecurityS2Utils.CryptoScalarmultCurve25519(s2, H(privateB), pa));
            Assert.AreEqual(shared, X(s1));
            Assert.AreEqual(shared, X(s2));
        }

        [Test]
        public void Aes128EcbEncrypt_MatchesNativeVector()
        {
            var output = new byte[16];
            SecurityS2Utils.Aes128EcbEncrypt(H("89AED3F81D42678CB1D6FB20456A8FB4"), H("94B9DE03284D7297BCE1062B50759ABF"), output);
            Assert.AreEqual("56C1BE4662803A5A6E99F10C3877B878", X(output));
        }

        [Test]
        public void AesCtrDrbg_MatchesNativeVector()
        {
            var ctx = new CTR_DRBG_CTX();
            var entropy = H("9FC4E90E33587DA2C7EC11365B80A5CAEF14395E83A8CDF2173C6186ABD0F51A");
            SecurityS2Utils.AesCtrDrbgInstantiate(ref ctx, entropy,
                H("AACFF4193E6388ADD2F71C41668BB0D5FA1F44698EB3D8FD22476C91B6DB0025"));
            Assert.AreEqual("001683A7F96DADB69DC653CFAE6CB90B476DE9E1D9F745C56E2364102099EC504500000000", X(ctx.GetBytes()));
            // libs2 leaves entropy ^ personalization in the entropy buffer.
            Assert.AreEqual("350B1D170D3BF50F151B0D773D0B151F150B7D370D1B150F357B0D171D0BF53F", X(entropy));

            var expected = new[]
            {
                new[] { "2265E1E6D28D229B2D9B92E5075DA91D", "00C492355CF6AFCA63ED413D5BC7D83EBE7801FBC11FE4362A5F117434D43839C700000000" },
                new[] { "45F3CFBEAD53A21C3BFB3BF21D9A5F39", "001226F7B4AE00B3900B69E96B7F59182B7975EA89584C3964D9E5757E2CA6EADD00000000" },
                new[] { "BDACB90AB957A44B0E1B340C8856C774", "009B1E46991A1D3EBF035BE222E441D7233D232F038D9AF62EFD567D8B7589287E00000000" },
            };
            foreach (var step in expected)
            {
                var output = new byte[16];
                SecurityS2Utils.AesCtrDrbgGenerate(ref ctx, output);
                Assert.AreEqual(step[0], X(output));
                Assert.AreEqual(step[1], X(ctx.GetBytes()));
            }
        }

        [Test]
        public void NextNonce_MatchesNativeVector()
        {
            var ctx = new CTR_DRBG_CTX();
            SecurityS2Utils.NextNonceInstantiate(ref ctx,
                H("B5DAFF24496E93B8DD02274C7196BBE0"),
                H("C0E50A2F54799EC3E80D32577CA1C6EB"),
                H("CBF0153A5F84A9CEF3183D6287ACD1F61B40658AAFD4F91E43688DB2D7FC2146"));
            Assert.AreEqual("002D7F7E028476C171BEAD45477D8817C9E29B2C6F51919309B9537D8C580229C800000000", X(ctx.GetBytes()));

            var saved = ctx.Clone();
            var expected = new[] { "B417728A3AD53CB380FB20EC779E265E", "648095D636FB1ACB898A2551153A8113", "E185AE8EFFF6F1CA8D287211DE2A1A04" };
            foreach (var nonce in expected)
            {
                var output = new byte[16];
                Assert.AreEqual(1, SecurityS2Utils.NextNonceGenerate(ref ctx, output));
                Assert.AreEqual(nonce, X(output));
            }
            Assert.AreEqual("002F3B42D209C30CD5E0C35233BF3D2E395CDFFB0607C982AA0D16A553D9F442F600000000", X(ctx.GetBytes()));

            // Skipping ahead lands on the same nonce, and a clone does not share state.
            var skipped = new byte[16];
            SecurityS2Utils.NextNonceGenerate(ref saved, skipped, 3);
            Assert.AreEqual(expected[2], X(skipped));
        }

        // RFC 4493, section 4
        [TestCase("", "BB1D6929E95937287FA37D129B756746")]
        [TestCase("6BC1BEE22E409F96E93D7E117393172A", "070A16B46B4D4144F79BDD9DD04A287C")]
        [TestCase("6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411", "DFA66747DE9AE63030CA32611497C827")]
        [TestCase("6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710", "51F0BEBF7E3B9D92FC49741779363CFE")]
        public void Cmac_MatchesRfc4493(string message, string mac)
        {
            Assert.AreEqual(mac, X(SecurityS2Managed.Cmac(H("2B7E151628AED2A6ABF7158809CF4F3C"), H(message))));
        }
    }
}
