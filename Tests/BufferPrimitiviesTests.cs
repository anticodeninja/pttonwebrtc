// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright 2019 Artem Yamshanov, me [at] anticode.ninja

﻿namespace Tests
{
    using NUnit.Framework;
    using PttOnWebRtc;

    [TestFixture]
    public class BufferPrimitiviesTests
    {
        [Test]
        public void BaseTest()
        {
            Assert.AreEqual(
                new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF},
                BufferPrimitivies.ParseHexStream("0123456789abcdefABCDEF"));
            Assert.AreEqual(
                "0123456789ABCDEF",
                BufferPrimitivies.ToHexStream(new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}));
        }
    }
}