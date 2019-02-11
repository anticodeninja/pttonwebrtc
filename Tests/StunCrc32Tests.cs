// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright 2019 Artem Yamshanov, me [at] anticode.ninja

﻿namespace Tests
{
    using NUnit.Framework;
    using PttOnWebRtc;

    [TestFixture]
    public class StunCrc32Tests
    {
        [Test]
        public void BaseTest()
        {
            Assert.AreEqual(0xD5333677, StunCrc32.Calc(BufferPrimitivies.ParseHexStream("0001004c2112a4422f3230767457754a415a343900060009397536793a39517757000000c0570004000200008029000881a33ba9b20f6d45002400046e7e1eff00080014131089f8e85bc61285b469e97314b264e24098e3")));
        }
    }
}