// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright 2019 Artem Yamshanov, me [at] anticode.ninja

namespace Tests
{
    using NUnit.Framework;
    using System.Linq;
    using PttOnWebRtc;

    [TestFixture]
    public class BufferPrimitivesTests
    {
        // ReSharper disable once InconsistentNaming
        private readonly byte[] MAGIC = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };

        [Test]
        public void HexHelpersTests()
        {
            var a = MAGIC.Concat(MAGIC.Skip(5)).ToArray();
            Assert.AreEqual(MAGIC.Concat(MAGIC.Skip(5)), BufferPrimitives.ParseHexStream("0123456789abcdefABCDEF"));
            Assert.AreEqual("0123456789ABCDEF", BufferPrimitives.ToHexStream(MAGIC));
        }

        [Test]
        public void GetBitsLocalOffsetTest()
        {
            var offset = 0;
            Assert.AreEqual(3, BufferPrimitives.GetBits(MAGIC, 7, ref offset, 2));
            Assert.AreEqual(2, BufferPrimitives.GetBits(MAGIC, 7, ref offset, 2));
            Assert.AreEqual(3, BufferPrimitives.GetBits(MAGIC, 7, ref offset, 2));
            Assert.AreEqual(3, BufferPrimitives.GetBits(MAGIC, 7, ref offset, 2));

            Assert.AreEqual(6, BufferPrimitives.GetBits(MAGIC, 6, 4, 3));
            Assert.AreEqual(7, BufferPrimitives.GetBits(MAGIC, 6, 7, 3));
            Assert.AreEqual(5, BufferPrimitives.GetBits(MAGIC, 7, 2, 3));
            Assert.AreEqual(7, BufferPrimitives.GetBits(MAGIC, 7, 5, 3));

            Assert.AreEqual(0x56, BufferPrimitives.GetBits(MAGIC, 2, 4, 8));
            Assert.AreEqual(0x5678, BufferPrimitives.GetBits(MAGIC, 2, 4, 16));
            Assert.AreEqual(0x56789A, BufferPrimitives.GetBits(MAGIC, 2, 4, 24));
            Assert.AreEqual(0x56789ABC, BufferPrimitives.GetBits(MAGIC, 2, 4, 32));
        }

        [Test]
        public void GetBitsGlobalOffsetTest()
        {
            var offset = 56;
            Assert.AreEqual(3, BufferPrimitives.GetBits(MAGIC, 0, ref offset, 2));
            Assert.AreEqual(2, BufferPrimitives.GetBits(MAGIC, 0, ref offset, 2));
            Assert.AreEqual(3, BufferPrimitives.GetBits(MAGIC, 0, ref offset, 2));
            Assert.AreEqual(3, BufferPrimitives.GetBits(MAGIC, 0, ref offset, 2));

            offset = 52;
            Assert.AreEqual(6, BufferPrimitives.GetBits(MAGIC, 0, ref offset, 3));
            Assert.AreEqual(7, BufferPrimitives.GetBits(MAGIC, 0, ref offset, 3));
            Assert.AreEqual(5, BufferPrimitives.GetBits(MAGIC, 0, ref offset, 3));
            Assert.AreEqual(7, BufferPrimitives.GetBits(MAGIC, 0, ref offset, 3));

            Assert.AreEqual(0x56, BufferPrimitives.GetBits(MAGIC, 0, 20, 8));
            Assert.AreEqual(0x5678, BufferPrimitives.GetBits(MAGIC, 0, 20, 16));
            Assert.AreEqual(0x56789A, BufferPrimitives.GetBits(MAGIC, 0, 20, 24));
            Assert.AreEqual(0x56789ABC, BufferPrimitives.GetBits(MAGIC, 0, 20, 32));
        }

        [Test]
        public void SetBitsLocalOffsetTest()
        {
            var offset = 0;
            var temp = MAGIC.Take(5).ToArray();
            BufferPrimitives.SetBits(temp, 3, ref offset, 2, 2);
            Assert.AreEqual(new byte[] { 0x01, 0x23, 0x45, 0xA7, 0x89 }, temp);
            BufferPrimitives.SetBits(temp, 3, ref offset, 2, 3);
            Assert.AreEqual(new byte[] { 0x01, 0x23, 0x45, 0xB7, 0x89 }, temp);
            BufferPrimitives.SetBits(temp, 3, ref offset, 2, 3);
            Assert.AreEqual(new byte[] { 0x01, 0x23, 0x45, 0xBF, 0x89 }, temp);
            BufferPrimitives.SetBits(temp, 3, ref offset, 2, 0);
            Assert.AreEqual(new byte[] { 0x01, 0x23, 0x45, 0xBC, 0x89 }, temp);

            temp = MAGIC.Take(5).ToArray();
            BufferPrimitives.SetBits(temp, 3, 4, 3, 6);
            Assert.AreEqual(new byte[] { 0x01, 0x23, 0x45, 0x6D, 0x89 }, temp);
            BufferPrimitives.SetBits(temp, 3, 7, 3, 7);
            Assert.AreEqual(new byte[] { 0x01, 0x23, 0x45, 0x6D, 0xC9 }, temp);
            BufferPrimitives.SetBits(temp, 4, 2, 3, 5);
            Assert.AreEqual(new byte[] { 0x01, 0x23, 0x45, 0x6D, 0xE9 }, temp);
            BufferPrimitives.SetBits(temp, 4, 5, 3, 7);
            Assert.AreEqual(new byte[] { 0x01, 0x23, 0x45, 0x6D, 0xEF }, temp);

            temp = MAGIC.Take(5).ToArray();
            BufferPrimitives.SetBits(temp, 3, 4, 8, 0xEF);
            Assert.AreEqual(new byte[] { 0x01, 0x23, 0x45, 0x6E, 0xF9 }, temp);
            BufferPrimitives.SetBits(temp, 2, 4, 16, 0xCDEF);
            Assert.AreEqual(new byte[] { 0x01, 0x23, 0x4C, 0xDE, 0xF9 }, temp);
            BufferPrimitives.SetBits(temp, 1, 4, 24, 0xABCDEF);
            Assert.AreEqual(new byte[] { 0x01, 0x2A, 0xBC, 0xDE, 0xF9 }, temp);
            BufferPrimitives.SetBits(temp, 0, 4, 32, 0x89ABCDEF);
            Assert.AreEqual(new byte[] { 0x08, 0x9A, 0xBC, 0xDE, 0xF9 }, temp);
        }

        [Test]
        public void SetBitsGlobalOffsetTest()
        {
            var offset = 24;
            var temp = MAGIC.Take(5).ToArray();
            BufferPrimitives.SetBits(temp, 0, ref offset, 2, 2);
            Assert.AreEqual(new byte[] { 0x01, 0x23, 0x45, 0xA7, 0x89 }, temp);
            BufferPrimitives.SetBits(temp, 0, ref offset, 2, 3);
            Assert.AreEqual(new byte[] { 0x01, 0x23, 0x45, 0xB7, 0x89 }, temp);
            BufferPrimitives.SetBits(temp, 0, ref offset, 2, 3);
            Assert.AreEqual(new byte[] { 0x01, 0x23, 0x45, 0xBF, 0x89 }, temp);
            BufferPrimitives.SetBits(temp, 0, ref offset, 2, 0);
            Assert.AreEqual(new byte[] { 0x01, 0x23, 0x45, 0xBC, 0x89 }, temp);

            offset = 28;
            temp = MAGIC.Take(5).ToArray();
            BufferPrimitives.SetBits(temp, 0, ref offset, 3, 6);
            Assert.AreEqual(new byte[] { 0x01, 0x23, 0x45, 0x6D, 0x89 }, temp);
            BufferPrimitives.SetBits(temp, 0, ref offset, 3, 7);
            Assert.AreEqual(new byte[] { 0x01, 0x23, 0x45, 0x6D, 0xC9 }, temp);
            BufferPrimitives.SetBits(temp, 0, ref offset, 3, 5);
            Assert.AreEqual(new byte[] { 0x01, 0x23, 0x45, 0x6D, 0xE9 }, temp);
            BufferPrimitives.SetBits(temp, 0, ref offset, 3, 7);
            Assert.AreEqual(new byte[] { 0x01, 0x23, 0x45, 0x6D, 0xEF }, temp);

            temp = MAGIC.Take(5).ToArray();
            BufferPrimitives.SetBits(temp, 0, 28, 8, 0xEF);
            Assert.AreEqual(new byte[] { 0x01, 0x23, 0x45, 0x6E, 0xF9 }, temp);
            BufferPrimitives.SetBits(temp, 0, 20, 16, 0xCDEF);
            Assert.AreEqual(new byte[] { 0x01, 0x23, 0x4C, 0xDE, 0xF9 }, temp);
            BufferPrimitives.SetBits(temp, 0, 12, 24, 0xABCDEF);
            Assert.AreEqual(new byte[] { 0x01, 0x2A, 0xBC, 0xDE, 0xF9 }, temp);
            BufferPrimitives.SetBits(temp, 0, 4, 32, 0x89ABCDEF);
            Assert.AreEqual(new byte[] { 0x08, 0x9A, 0xBC, 0xDE, 0xF9 }, temp);
        }
    }
}