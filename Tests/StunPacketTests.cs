// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright 2019 Artem Yamshanov, me [at] anticode.ninja

﻿namespace Tests
{
    using System.Net;
    using System.Text;

    using NUnit.Framework;

    using PttOnWebRtc;

    [TestFixture]
    public class StunPacketTests
    {
        [Test]
        public void BindingRequestParse()
        {
            var input = BufferPrimitivies.ParseHexStream("000100002112a44261534344636d466568656253");
            Assert.AreEqual(StunPacket.ResultCodes.Ok, StunPacket.TryParse(input, out var output));
            Assert.AreEqual(StunPacket.MessageTypes.BindingRequest, output.MessageType);
            Assert.AreEqual(StunPacket.MessageClasses.Request, output.MessageClass);
            Assert.AreEqual(StunPacket.MessageMethods.Binding, output.MessageMethod);
            Assert.AreEqual(BufferPrimitivies.ParseHexStream("61534344636d466568656253"), output.TransactionId);
        }

        [Test]
        public void BindingRequestPack()
        {
            var input = new StunPacket
            {
                MessageClass = StunPacket.MessageClasses.Request,
                MessageMethod = StunPacket.MessageMethods.Binding,
                TransactionId = BufferPrimitivies.ParseHexStream("61534344636d466568656253"),
            };

            Assert.AreEqual(BufferPrimitivies.ParseHexStream("000100002112a44261534344636d466568656253"), input.Pack());
        }

        [Test]
        public void BindingResponseParse()
        {
            var input = BufferPrimitivies.ParseHexStream("0101000c2112a44261534344636d4665686562530020000800018a54e1baa549");
            Assert.AreEqual(StunPacket.ResultCodes.Ok, StunPacket.TryParse(input, out var output));
            Assert.AreEqual(StunPacket.MessageTypes.BindingSuccessResponse, output.MessageType);
            Assert.AreEqual(StunPacket.MessageClasses.SuccessResponse, output.MessageClass);
            Assert.AreEqual(StunPacket.MessageMethods.Binding, output.MessageMethod);
            Assert.AreEqual(BufferPrimitivies.ParseHexStream("61534344636d466568656253"), output.TransactionId);
            Assert.AreEqual(new IPEndPoint(new IPAddress(new byte[] { 192, 168, 1, 11}), 43846), output.XorMappedAddress);
        }

        [Test]
        public void BindingResponsePack()
        {
            var input = new StunPacket
            {
                MessageClass = StunPacket.MessageClasses.SuccessResponse,
                MessageMethod = StunPacket.MessageMethods.Binding,
                TransactionId = BufferPrimitivies.ParseHexStream("61534344636d466568656253"),
                XorMappedAddress = new IPEndPoint(new IPAddress(new byte[] { 192, 168, 1, 11}), 43846),
            };

            Assert.AreEqual(BufferPrimitivies.ParseHexStream("0101000c2112a44261534344636d4665686562530020000800018a54e1baa549"), input.Pack());
        }

        [Test]
        public void BindingResponseBackwardParse()
        {
            var input = BufferPrimitivies.ParseHexStream("010100242112a44261534344636d466568656253000100080001ab46c0a8010b802b000800010d96c0a801040020000800018a54e1baa549");
            Assert.AreEqual(StunPacket.ResultCodes.Ok, StunPacket.TryParse(input, out var output));
            Assert.AreEqual(StunPacket.MessageTypes.BindingSuccessResponse, output.MessageType);
            Assert.AreEqual(StunPacket.MessageClasses.SuccessResponse, output.MessageClass);
            Assert.AreEqual(StunPacket.MessageMethods.Binding, output.MessageMethod);
            Assert.AreEqual(BufferPrimitivies.ParseHexStream("61534344636d466568656253"), output.TransactionId);
            Assert.AreEqual(new IPEndPoint(new IPAddress(new byte[] { 192, 168, 1, 11}), 43846), output.MappedAddress);
            Assert.AreEqual(new IPEndPoint(new IPAddress(new byte[] { 192, 168, 1, 4}), 3478), output.ResponseOrigin);
            Assert.AreEqual(new IPEndPoint(new IPAddress(new byte[] { 192, 168, 1, 11}), 43846), output.XorMappedAddress);
        }

        [Test]
        public void BindingResponseBackwardPack()
        {
            var input = new StunPacket
            {
                MessageClass = StunPacket.MessageClasses.SuccessResponse,
                MessageMethod = StunPacket.MessageMethods.Binding,
                TransactionId = BufferPrimitivies.ParseHexStream("61534344636d466568656253"),
                MappedAddress = new IPEndPoint(new IPAddress(new byte[] { 192, 168, 1, 11}), 43846),
                ResponseOrigin = new IPEndPoint(new IPAddress(new byte[] { 192, 168, 1, 4}), 3478),
                XorMappedAddress = new IPEndPoint(new IPAddress(new byte[] { 192, 168, 1, 11}), 43846),
            };

            Assert.AreEqual(BufferPrimitivies.ParseHexStream("010100242112a44261534344636d466568656253000100080001ab46c0a8010b0020000800018a54e1baa549802b000800010d96c0a80104"), input.Pack());
        }

        [Test]
        public void BindingRequestIceParse()
        {
            var input = BufferPrimitivies.ParseHexStream("0001004c2112a4422f3230767457754a415a343900060009397536793a39517757000000c0570004000200008029000881a33ba9b20f6d45002400046e7e1eff00080014131089f8e85bc61285b469e97314b264e24098e38028000486676339");
            Assert.AreEqual(StunPacket.ResultCodes.Ok, StunPacket.TryParse(input, out var output));
            Assert.AreEqual(StunPacket.MessageTypes.BindingRequest, output.MessageType);
            Assert.AreEqual(StunPacket.MessageClasses.Request, output.MessageClass);
            Assert.AreEqual(StunPacket.MessageMethods.Binding, output.MessageMethod);
            Assert.AreEqual(BufferPrimitivies.ParseHexStream("2f3230767457754a415a3439"), output.TransactionId);
            Assert.AreEqual("9u6y:9QwW", output.Username);
            Assert.AreEqual(0x81a33ba9b20f6d45, output.IceControlledTieBreaker);
            Assert.AreEqual(1853759231, output.Priority);
            Assert.AreEqual(BufferPrimitivies.ParseHexStream("131089f8e85bc61285b469e97314b264e24098e3"), output.MessageIntegrity);
            Assert.AreEqual(true, output.Fingerprint);
            Assert.IsTrue(output.VerifyIntegrity(Encoding.UTF8.GetBytes("2bosGehEV5BaY5xf3t4EJeII")));
        }

        [Test]
        public void BindingRequestIcePack()
        {
            var input = new StunPacket
            {
                MessageClass = StunPacket.MessageClasses.Request,
                MessageMethod = StunPacket.MessageMethods.Binding,
                TransactionId = BufferPrimitivies.ParseHexStream("2f3230767457754a415a3439"),
                Username = "9u6y:9QwW",
                IceControlledTieBreaker = 0x81a33ba9b20f6d45,
                Priority = 1853759231,
                MessageIntegrityKey = Encoding.UTF8.GetBytes("2bosGehEV5BaY5xf3t4EJeII"),
                Fingerprint = true,
            };

            Assert.AreEqual(BufferPrimitivies.ParseHexStream("000100442112a4422f3230767457754a415a343900060009397536793a39517757000000002400046e7e1eff8029000881a33ba9b20f6d45000800149813ea94319ab9bc982e2793b16c2f9ce6f1376c80280004a3f6fd3c"), input.Pack());
        }

        [Test]
        public void BindingResponseIceParse()
        {
            var input = BufferPrimitivies.ParseHexStream("0101002c2112a4422f3230767457754a415a3439002000080001cd97e1baa546000800140f966d9872873fb87da48206a40ef8933f1c483980280004d43b7dae");
            Assert.AreEqual(StunPacket.ResultCodes.Ok, StunPacket.TryParse(input, out var output));
            Assert.AreEqual(StunPacket.MessageTypes.BindingSuccessResponse, output.MessageType);
            Assert.AreEqual(StunPacket.MessageClasses.SuccessResponse, output.MessageClass);
            Assert.AreEqual(StunPacket.MessageMethods.Binding, output.MessageMethod);
            Assert.AreEqual(BufferPrimitivies.ParseHexStream("2f3230767457754a415a3439"), output.TransactionId);
            Assert.AreEqual(new IPEndPoint(new IPAddress(new byte[] { 192, 168, 1, 4}), 60549), output.XorMappedAddress);
            Assert.AreEqual(BufferPrimitivies.ParseHexStream("0f966d9872873fb87da48206a40ef8933f1c4839"), output.MessageIntegrity);
            Assert.AreEqual(true, output.Fingerprint);
            Assert.IsTrue(output.VerifyIntegrity(Encoding.UTF8.GetBytes("2bosGehEV5BaY5xf3t4EJeII")));
        }

        [Test]
        public void BindingResponseIcePack()
        {
            var input = new StunPacket
            {
                MessageClass = StunPacket.MessageClasses.SuccessResponse,
                MessageMethod = StunPacket.MessageMethods.Binding,
                TransactionId = BufferPrimitivies.ParseHexStream("2f3230767457754a415a3439"),
                XorMappedAddress = new IPEndPoint(new IPAddress(new byte[] { 192, 168, 1, 4}), 60549),
                MessageIntegrityKey = Encoding.UTF8.GetBytes("2bosGehEV5BaY5xf3t4EJeII"),
                Fingerprint = true,
            };

            Assert.AreEqual(BufferPrimitivies.ParseHexStream("0101002c2112a4422f3230767457754a415a3439002000080001cd97e1baa546000800140f966d9872873fb87da48206a40ef8933f1c483980280004d43b7dae"), input.Pack());
        }
    }
}