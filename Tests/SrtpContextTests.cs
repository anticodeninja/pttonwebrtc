// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright 2019 Artem Yamshanov, me [at] anticode.ninja

namespace Tests
{
    using System.Linq;
    using System.Text;

    using NUnit.Framework;

    using PttOnWebRtc;

    [TestFixture]
    public class SrtpContextTests
    {
        [Test]
        public void AesCmTestVector()
        {
            var ctx = new SrtpContext();

            var keyStream = new byte[48];

            ctx.GenerateKeyStream(
                BufferPrimitivies.ParseHexStream("2B7E151628AED2A6ABF7158809CF4F3C"),
                BufferPrimitivies.ParseHexStream("F0F1F2F3F4F5F6F7F8F9FAFBFCFD0000"),
                keyStream);
            CollectionAssert.AreEqual(
                BufferPrimitivies.ParseHexStream("E03EAD0935C95E80E166B16DD92B4EB4" +
                                                 "D23513162B02D0F72A43A2FE4A5F97AB" +
                                                 "41E95B3BB0A2E8DD477901E4FCA894C0"),
                keyStream);

            ctx.GenerateKeyStream(
                BufferPrimitivies.ParseHexStream("2B7E151628AED2A6ABF7158809CF4F3C"),
                BufferPrimitivies.ParseHexStream("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF"),
                keyStream);
            CollectionAssert.AreEqual(
                BufferPrimitivies.ParseHexStream("EC8CDF7398607CB0F2D21675EA9EA1E4" +
                                                 "362B7C3C6773516318A077D7FC5073AE" +
                                                 "6A2CC3787889374FBEB4C81B17BA6C44"),
                keyStream);
        }

        [Test]
        public void KeyDerivationTestVectors()
        {
            var ctx = new SrtpContext();

            var sessionKey = new byte[16];
            var sessionSalt = new byte[16];
            var sessionAuth = new byte[96];

            ctx.GenerateSessionKey(
                BufferPrimitivies.ParseHexStream("E1F97A0D3E018BE0D64FA32C06DE4139"),
                BufferPrimitivies.ParseHexStream("0EC675AD498AFEEBB6960B3AABE6"),
                sessionKey,
                sessionSalt,
                sessionAuth);

            CollectionAssert.AreEqual(
                BufferPrimitivies.ParseHexStream("C61E7A93744F39EE10734AFE3FF7A087"),
                sessionKey);
            CollectionAssert.AreEqual(
                BufferPrimitivies.ParseHexStream("30CBBC08863D8C85D49DB34A9AE17AC6"),
                sessionSalt);
            CollectionAssert.AreEqual(
                BufferPrimitivies.ParseHexStream("CEBE321F6FF7716B6FD4AB49AF256A15" +
                                                 "6D38BAA48F0A0ACF3C34E2359E6CDBCE" +
                                                 "E049646C43D9327AD175578EF7227098" +
                                                 "6371C10C9A369AC2F94A8C5FBCDDDC25" +
                                                 "6D6E919A48B610EF17C2041E47403576" +
                                                 "6B68642C59BBFC2F34DB60DBDFB2DC68"),
                sessionAuth);
        }

        [Test]
        public void HmacTest()
        {
            var ctx = new SrtpContext();
            var hmac = new byte[SrtpContext.HMAC_SHA1_SIZE];

            ctx.CalcHmac(
                BufferPrimitivies.ParseHexStream("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), 20,
                Encoding.UTF8.GetBytes("Hi There"), 8,
                hmac);
            CollectionAssert.AreEqual(
                BufferPrimitivies.ParseHexStream("b617318655057264e28bc0b6fb378c8ef146be00"),
                hmac);

            ctx.CalcHmac(
                Encoding.UTF8.GetBytes("Jefe"), 4,
                Encoding.UTF8.GetBytes("what do ya want for nothing?"), 28,
                hmac);
            CollectionAssert.AreEqual(
                BufferPrimitivies.ParseHexStream("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"),
                hmac);

            ctx.CalcHmac(
                BufferPrimitivies.ParseHexStream("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), 20,
                Enumerable.Range(0, 50).Select(_ => (byte)0xdd).ToArray(), 50,
                hmac);
            CollectionAssert.AreEqual(
                BufferPrimitivies.ParseHexStream("125d7342b9ac11cd91a39af48aa17b4f63f175d3"),
                hmac);
        }

        [Test]
        public void ParseSrtpPacketLibSrtp()
        {
            var ctx = new SrtpContext();

            ctx.SetMasterKeys(
                BufferPrimitivies.ParseHexStream("00000000000000000000000000000000"),
                BufferPrimitivies.ParseHexStream("0000000000000000000000000000"),
                BufferPrimitivies.ParseHexStream("E1F97A0D3E018BE0D64FA32C06DE4139"),
                BufferPrimitivies.ParseHexStream("0EC675AD498AFEEBB6960B3AABE6"));

            if (ctx.TryParseSrtpPacket(
                BufferPrimitivies.ParseHexStream("800F1234DECAFBADCAFEBABE4E55DC4CE79978D88CA4D215949D2402B78D6ACC99EA179B8DBB"),
                out var rtpPacket) != RtpPacket.ResultCodes.Ok)
               Assert.Fail("Cannot unpack srtpPacket");

            CollectionAssert.AreEqual(
                BufferPrimitivies.ParseHexStream("ABABABABABABABABABABABABABABABAB"),
                rtpPacket.Payload);
        }

        [Test]
        public void PackSrtpPacketLibSrtp()
        {
            var ctx = new SrtpContext();
            ctx.SetMasterKeys(
                BufferPrimitivies.ParseHexStream("E1F97A0D3E018BE0D64FA32C06DE4139"),
                BufferPrimitivies.ParseHexStream("0EC675AD498AFEEBB6960B3AABE6"),
                BufferPrimitivies.ParseHexStream("00000000000000000000000000000000"),
                BufferPrimitivies.ParseHexStream("0000000000000000000000000000"));

            var rtpPacket = new RtpPacket
            {
                Payload = BufferPrimitivies.ParseHexStream("ABABABABABABABABABABABABABABABAB"),
                PayloadType = 0x0F,
                SequenceNumber = 0x1234,
                Ssrc = 0xCAFEBABE,
                Timestamp = 0xDECAFBAD,
            };

            CollectionAssert.AreEqual(
                BufferPrimitivies.ParseHexStream("800F1234DECAFBADCAFEBABE4E55DC4CE79978D88CA4D215949D2402B78D6ACC99EA179B8DBB"),
                ctx.PackSrtpPacket(rtpPacket));
        }

        [Test]
        public void ParseSrtpPacketReal()
        {
            var ctx = new SrtpContext();

            ctx.SetMasterKeys(
                BufferPrimitivies.ParseHexStream("00000000000000000000000000000000"),
                BufferPrimitivies.ParseHexStream("0000000000000000000000000000"),
                BufferPrimitivies.ParseHexStream("F4741D27D75AAEA76ABCCA98C03DB931"),
                BufferPrimitivies.ParseHexStream("F4C375B9F90823019060B3FC3AC5"));

            if (ctx.TryParseSrtpPacket(
                    BufferPrimitivies.ParseHexStream("8080488070C7E0A6B695617903141F73CAF634C2F9B2D0FA909C1CC5D5EEECF02A27C118735D9FEACE9B7D37FE29FBAB5D4D2F2A8EB1B6C7AECE93703211BA40BF4706D084655A6DD0B2398FA2A213405C794908E24B99DB901072E1E165B0A6AAB086B704D5176373F72297E2CA3786B7240DF14F97C065DCD29F040E0F184680CA4E1F93B948495BC8D485C8B484C558D9A11BA0C0001B176F2CA09DFF327FF2FB2AE314BF52F22AEC34A96269E7D5775AE92DDF4C"),
                    out var rtpPacket) != RtpPacket.ResultCodes.Ok)
               Assert.Fail("Cannot unpack srtpPacket");
            CollectionAssert.AreEqual(
                Enumerable.Range(0, 160).Select(_ => (byte)0xff),
                rtpPacket.Payload);

            if (ctx.TryParseSrtpPacket(
                    BufferPrimitivies.ParseHexStream("8000488170C7E146B6956179F2193668F88A223F3A40560D876E837CD178256CE01CEB847A2134FC03213F4D57D728C331678E2C4F5DCA0CBBDFE67140D0C0D85921219EDAFCEDA30B03B86830DB045CFED45AF34E004194ACCA9121F22303DE57BC72B1783C86E64DFC92940CD254BA4A996EF73837BD56018DF1FF1F4D9F41946BF268584B6276F09F32DFD361201B84DA439DDA0A076AC36D2840263C39B90114F938E1CEFAA3ED3DD430025298DE15F0D406078A"),
                    out rtpPacket) != RtpPacket.ResultCodes.Ok)
               Assert.Fail("Cannot unpack srtpPacket");
            CollectionAssert.AreEqual(
                Enumerable.Range(0, 160).Select(_ => (byte)0xff),
                rtpPacket.Payload);

            if (ctx.TryParseSrtpPacket(
                    BufferPrimitivies.ParseHexStream("8000488270C7E1E6B69561797C9C3C5FE6854AA81AEF920F7B771FCED9C04B0E2E84216C4D84757E9E98E05232140CA3BD19DA26EF6581AE4E5CAAC13032F4889E7EBFAC7391EEA5B250C48D7779C1F6E4D6DFEB63CACD2105819B2A6A322D46FE726876891927725256B017877D59AB5FEFFDFDB51190C6A02649D198F2C6ECA54402EDCA4DE9C73F41992ABE1B259470AC6AB0A6EC8E462A001A129FF38589EC8C781272D8BBC14AD2D2365C6CBA8A18FE080F5150"),
                    out rtpPacket) != RtpPacket.ResultCodes.Ok)
               Assert.Fail("Cannot unpack srtpPacket");
            CollectionAssert.AreEqual(
                Enumerable.Range(0, 160).Select(_ => (byte)0xff),
                rtpPacket.Payload);
        }

        [Test]
        public void PackSrtpPacketReal()
        {
            var ctx = new SrtpContext();

            ctx.SetMasterKeys(
                BufferPrimitivies.ParseHexStream("F4741D27D75AAEA76ABCCA98C03DB931"),
                BufferPrimitivies.ParseHexStream("F4C375B9F90823019060B3FC3AC5"),
                BufferPrimitivies.ParseHexStream("00000000000000000000000000000000"),
                BufferPrimitivies.ParseHexStream("0000000000000000000000000000"));

            var rtpPacket = new RtpPacket
            {
                Marker = true,
                Payload = Enumerable.Range(0, 160).Select(_ => (byte)0xff).ToArray(),
                PayloadType = 0x00,
                SequenceNumber = 0x4880,
                Ssrc = 0xB6956179,
                Timestamp = 0x70C7E0A6,
            };

            CollectionAssert.AreEqual(
                BufferPrimitivies.ParseHexStream("8080488070C7E0A6B695617903141F73CAF634C2F9B2D0FA909C1CC5D5EEECF02A27C118735D9FEACE9B7D37FE29FBAB5D4D2F2A8EB1B6C7AECE93703211BA40BF4706D084655A6DD0B2398FA2A213405C794908E24B99DB901072E1E165B0A6AAB086B704D5176373F72297E2CA3786B7240DF14F97C065DCD29F040E0F184680CA4E1F93B948495BC8D485C8B484C558D9A11BA0C0001B176F2CA09DFF327FF2FB2AE314BF52F22AEC34A96269E7D5775AE92DDF4C"),
                ctx.PackSrtpPacket(rtpPacket));

            rtpPacket.Marker = false;
            rtpPacket.SequenceNumber = 0x4881;
            rtpPacket.Timestamp = 0x70C7E146;

            CollectionAssert.AreEqual(
                BufferPrimitivies.ParseHexStream("8000488170C7E146B6956179F2193668F88A223F3A40560D876E837CD178256CE01CEB847A2134FC03213F4D57D728C331678E2C4F5DCA0CBBDFE67140D0C0D85921219EDAFCEDA30B03B86830DB045CFED45AF34E004194ACCA9121F22303DE57BC72B1783C86E64DFC92940CD254BA4A996EF73837BD56018DF1FF1F4D9F41946BF268584B6276F09F32DFD361201B84DA439DDA0A076AC36D2840263C39B90114F938E1CEFAA3ED3DD430025298DE15F0D406078A"),
                ctx.PackSrtpPacket(rtpPacket));

            rtpPacket.SequenceNumber = 0x4882;
            rtpPacket.Timestamp = 0x70C7E1E6;

                CollectionAssert.AreEqual(
                BufferPrimitivies.ParseHexStream("8000488270C7E1E6B69561797C9C3C5FE6854AA81AEF920F7B771FCED9C04B0E2E84216C4D84757E9E98E05232140CA3BD19DA26EF6581AE4E5CAAC13032F4889E7EBFAC7391EEA5B250C48D7779C1F6E4D6DFEB63CACD2105819B2A6A322D46FE726876891927725256B017877D59AB5FEFFDFDB51190C6A02649D198F2C6ECA54402EDCA4DE9C73F41992ABE1B259470AC6AB0A6EC8E462A001A129FF38589EC8C781272D8BBC14AD2D2365C6CBA8A18FE080F5150"),
                ctx.PackSrtpPacket(rtpPacket));
        }
    }
}