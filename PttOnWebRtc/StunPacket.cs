// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright 2019 Artem Yamshanov, me [at] anticode.ninja

﻿namespace PttOnWebRtc
{
    using System;
    using System.Net.Sockets;
    using System.Security.Cryptography;
    using System.Net;
    using System.Text;

    public class StunPacket
    {
        private const int HEADER_SIZE = 20;
        private const int BUFFER_SIZE = 512;
        private const int HMAC_TAG_SIZE = 24;
        private const uint MAGIC_COOKIE = 0x2112A442;
        private const uint FINGERPRINT_MASK = 0x5354554E;

        public enum MessageTypes
        {
            BindingRequest = 0x0001,
            BindingSuccessResponse = 0x0101,
        }

        public enum MessageClasses
        {
            Request = 0x00,
            Indication = 0x01,
            SuccessResponse = 0x02,
            ErrorResponse = 0x03,
        }

        public enum MessageMethods
        {
            Binding = 0x0001,
        }

        public enum Tags
        {
            Reserved = 0x0000,
            MappedAddress = 0x0001,
            ResponseAddress = 0x0002,
            ChangeAddress = 0x0003,
            SourceAddress = 0x0004,
            ChangedAddress = 0x0005,
            Username = 0x0006,
            Password = 0x0007,
            MessageIntegrity = 0x0008,
            ErrorCode = 0x0009,
            UnknownAttributes = 0x000A,
            ReflectFrom = 0x000B,
            Realm = 0x0014,
            Nonce = 0x0015,
            XorMappedAddress = 0x0020,
            Software = 0x8022,
            AlternateServer = 0x8023,
            Priority = 0x0024,
            UseCandidate = 0x0025,
            Fingerprint = 0x8028,
            IceControlled = 0x8029,
            IceControlling = 0x802A,
            ResponseOrigin = 0x802B,
        }

        public enum ErrorCodes
        {
            TryAlternate = 300,
            BadRequest = 400, // TODO
            Unathorized = 401,
            UnknownAttribute = 420,
            StaleNonce = 438,
            RoleConflict = 487,
            ServerError = 500,
        }

        public enum ResultCodes
        {
            Ok,
            PacketIsNotStun,
            UnknownAttribute,
            IncorrectAttribute,
            IntegrityNotCorrect,
        }

        public MessageTypes MessageType { get; set; }

        public MessageClasses MessageClass
        {
            get => (MessageClasses) ((((int)MessageType & 0x100) >> 7) | (((int)MessageType & 0x10) >> 4));
            set => MessageType = (MessageTypes) (((int)MessageType & 0x3EEF) | (((int)value << 7) & 0x100) | (((int)value << 4) & 0x10));
        }

        public MessageMethods MessageMethod
        {
            get => (MessageMethods) ((((int)MessageType & 0x3E00) >> 2) | (((int)MessageType & 0xE0) >> 1) | ((int)MessageType & 0x0F));
            set => MessageType = (MessageTypes) (((int)MessageType & 0x110) | (((int)value << 2) & 0x3E00) | (((int)value << 1) & 0xE0) | ((int)value & 0x0F));
        }

        public byte[] MagicCookie { get; set; }

        public byte[] TransactionId { get; set; }

        public IPEndPoint MappedAddress { get; set; }

        public string Username { get; set; }

        public string Password { get; set; }

        public IPEndPoint XorMappedAddress { get; set; }

        public uint? Priority { get; set; }

        public byte[] MessageIntegrityInput { get; set; }

        public byte[] MessageIntegrityKey { get; set; }

        public byte[] MessageIntegrity { get; set; }

        public bool UseCandidate { get; set; }

        public bool Fingerprint { get; set; }

        public ulong? IceControlledTieBreaker { get; set; }

        public ulong? IceControllingTieBreaker { get; set; }

        public IPEndPoint ResponseOrigin { get; set; }

        public static ResultCodes TryParse(byte[] buffer, out StunPacket output)
        {
            var offset = 0;
            return TryParse(buffer, ref offset, out output);
        }

        public static ResultCodes TryParse(byte[] buffer, ref int offset, out StunPacket output)
        {
            output = null;

            var endOffset = offset + HEADER_SIZE;
            if (endOffset > buffer.Length)
                return ResultCodes.PacketIsNotStun;

            if ((buffer[offset] & 0xC0) != 0)
                return ResultCodes.PacketIsNotStun;

            endOffset = endOffset + BufferPrimitivies.GetUint16(buffer, offset + 2);
            if (endOffset > buffer.Length)
                return ResultCodes.PacketIsNotStun;

            if (BufferPrimitivies.GetUint32(buffer, offset + 4) != MAGIC_COOKIE)
                return ResultCodes.PacketIsNotStun;

            var temp = new StunPacket();

            var startOffset = offset;

            temp.MessageType = (MessageTypes) BufferPrimitivies.GetUint16(buffer, ref offset);

            offset += 6; // Message length and magic cookie

            temp.TransactionId = BufferPrimitivies.GetBytes(buffer, ref offset, 12);

            while (offset < endOffset)
            {
                if (endOffset - offset < 4)
                    return ResultCodes.IncorrectAttribute;

                var type = BufferPrimitivies.GetUint16(buffer, ref offset);
                var length = BufferPrimitivies.GetUint16(buffer, ref offset);
                var tagEndOffset = offset + (length + 3) / 4 * 4;

                if (tagEndOffset > endOffset)
                    return ResultCodes.IncorrectAttribute;

                switch ((Tags)type)
                {
                    case Tags.MappedAddress:
                        if (temp.MappedAddress != null) break;
                        temp.MappedAddress = ParseAddress(buffer, ref offset, length, null);
                        if (temp.MappedAddress == null) return ResultCodes.IncorrectAttribute;
                        break;

                    case Tags.ResponseAddress:
                        break;

                    case Tags.ChangeAddress:
                        break;

                    case Tags.SourceAddress:
                        break;

                    case Tags.ChangedAddress:
                        break;

                    case Tags.Username:
                        if (temp.Username != null) break;
                        temp.Username = Encoding.UTF8.GetString(buffer, offset, length);
                        if (temp.Username == null) return ResultCodes.IncorrectAttribute;
                        break;

                    case Tags.Password:
                        break;

                    case Tags.MessageIntegrity:
                        if (length != 20) return ResultCodes.IncorrectAttribute;
                        temp.MessageIntegrity = BufferPrimitivies.GetBytes(buffer, ref offset, 20);
                        temp.MessageIntegrityInput = BufferPrimitivies.GetBytes(buffer, startOffset, offset - startOffset - HMAC_TAG_SIZE);
                        BufferPrimitivies.SetUint16(temp.MessageIntegrityInput, 2, (ushort) (offset - startOffset - HEADER_SIZE));
                        break;

                    case Tags.ErrorCode:
                        break;
                    case Tags.UnknownAttributes:
                        break;
                    case Tags.ReflectFrom:
                        break;
                    case Tags.Realm:
                        break;
                    case Tags.Nonce:
                        break;

                    case Tags.XorMappedAddress:
                        if (temp.XorMappedAddress != null) break;
                        temp.XorMappedAddress = ParseAddress(buffer, ref offset, length, temp.TransactionId);
                        if (temp.XorMappedAddress == null) return ResultCodes.IncorrectAttribute;
                        break;

                    case Tags.Software:
                        break;

                    case Tags.AlternateServer:
                        break;

                    case Tags.Priority:
                        if (temp.Priority != null) break;
                        if (length != 4) return ResultCodes.IncorrectAttribute;
                        temp.Priority = BufferPrimitivies.GetUint32(buffer, ref offset);
                        break;

                    case Tags.UseCandidate:
                        temp.UseCandidate = true;
                        break;

                    case Tags.Fingerprint:
                        if (length != 4) return ResultCodes.IncorrectAttribute;
                        var actualFingerprint = BufferPrimitivies.GetUint32(buffer, ref offset);
                        var calcFingerprint = StunCrc32.Calc(buffer, startOffset, endOffset - startOffset - 8) ^ FINGERPRINT_MASK;
                        if (calcFingerprint != actualFingerprint) return ResultCodes.PacketIsNotStun;
                        temp.Fingerprint = true;
                        break;

                    case Tags.IceControlled:
                        if (temp.IceControlledTieBreaker != null) break;
                        if (length != 8) return ResultCodes.IncorrectAttribute;;
                        temp.IceControlledTieBreaker = BufferPrimitivies.GetUint64(buffer, ref offset);
                        break;

                    case Tags.IceControlling:
                        if (temp.IceControllingTieBreaker != null) break;
                        if (length != 8) return ResultCodes.IncorrectAttribute;;
                        temp.IceControllingTieBreaker = BufferPrimitivies.GetUint64(buffer, ref offset);
                        break;

                    case Tags.ResponseOrigin:
                        if (temp.ResponseOrigin != null) break;
                        temp.ResponseOrigin = ParseAddress(buffer, ref offset, length, null);
                        if (temp.ResponseOrigin == null) return ResultCodes.IncorrectAttribute;
                        break;

                    default:
                        if (type < 0x8000) return ResultCodes.UnknownAttribute;
                        // Ignore
                        break;
                }

                offset = tagEndOffset;
            }

            output = temp;
            return ResultCodes.Ok;
        }

        private bool ValidateHmac(byte[] calc)
        {
            if (MessageIntegrity == null || calc == null)
                return false;

            for (var i = 0; i < calc.Length; ++i)
                if (calc[i] != MessageIntegrity[i])
                    return false;

            return true;
        }

        private byte[] CalcHmac(byte[] key)
        {
            return new HMACSHA1(key).ComputeHash(MessageIntegrityInput);
        }

        private static IPEndPoint ParseAddress(byte[] buffer, ref int offset, int length, byte[] transactionId)
        {
            if (length < 4) return null;

            offset += 1;
            var type = BufferPrimitivies.GetUint8(buffer, ref offset);

            var portMask = transactionId != null ? (MAGIC_COOKIE >> 16) : 0;
            var port = (ushort)(BufferPrimitivies.GetUint16(buffer, ref offset) ^ portMask);

            byte[] address = null;
            byte[] mask = null;

            switch (type)
            {
                case 0x01:
                    if (length != 8) break;
                    address = BufferPrimitivies.GetBytes(buffer, offset, 4);
                    if (transactionId != null)
                    {
                        mask = new byte[4];
                        BufferPrimitivies.SetUint32(mask, 0, MAGIC_COOKIE);
                    }
                    break;
                case 0x02:
                    if (length != 20) break;
                    address = BufferPrimitivies.GetBytes(buffer, offset, 16);
                    if (transactionId != null)
                    {
                        mask = new byte[16];
                        BufferPrimitivies.SetUint32(mask, 0, MAGIC_COOKIE);
                        BufferPrimitivies.SetBytes(mask, 4, transactionId);
                    }
                    break;
            }

            if (address == null)
                return null;

            if (mask != null)
            {
                for (var i = 0; i < address.Length; ++i)
                    address[i] ^= mask[i];
            }

            return new IPEndPoint(new IPAddress(address), port);
        }

        private void PackAddress(byte[] buffer, IPEndPoint data, ref int offset, byte[] transactionId)
        {
            byte type = 0;
            byte[] address = null;
            byte[] mask = null;

            if (data.AddressFamily == AddressFamily.InterNetwork)
            {
                type = 1;
                address = data.Address.GetAddressBytes();
                if (transactionId != null)
                {
                    mask = new byte[4];
                    BufferPrimitivies.SetUint32(mask, 0, MAGIC_COOKIE);
                }
            }
            else if (data.AddressFamily == AddressFamily.InterNetworkV6)
            {
                type = 2;
                address = data.Address.GetAddressBytes();
                if (transactionId != null)
                {
                    mask = new byte[16];
                    BufferPrimitivies.SetUint32(mask, 0, MAGIC_COOKIE);
                    BufferPrimitivies.SetBytes(mask, 4, transactionId);
                }
            }

            var portMask = transactionId != null ? (MAGIC_COOKIE >> 16) : 0;

            if (mask != null)
            {
                for (var i = 0; i < address.Length; ++i)
                    address[i] ^= mask[i];
            }

            BufferPrimitivies.SetUint8(buffer, ref offset, 0);
            BufferPrimitivies.SetUint8(buffer, ref offset, type);
            BufferPrimitivies.SetUint16(buffer, ref offset, (ushort) (data.Port ^ portMask));
            BufferPrimitivies.SetBytes(buffer, ref offset, address);
        }

        public byte[] Pack()
        {
            var buffer = new byte[BUFFER_SIZE];
            int offset = 0;
            Pack(buffer, ref offset);
            Array.Resize(ref buffer, offset);
            return buffer;
        }

        private int StartTag(byte[] buffer, ref int offset, Tags tag)
        {
            var startTagOffset = offset;
            BufferPrimitivies.SetUint16(buffer, ref offset, (ushort) tag);
            offset += 2;
            return startTagOffset;
        }

        private void StopTag(byte[] buffer, ref int offset, int startTagOffset)
        {
            BufferPrimitivies.SetUint16(buffer, startTagOffset + 2, (ushort) (offset - startTagOffset - 4));
            offset = startTagOffset + (offset - startTagOffset + 3) / 4 * 4;
        }

        private void Pack(byte[] buffer, ref int offset)
        {
            var startOffset = offset;
            BufferPrimitivies.SetUint16(buffer, ref offset, (ushort) MessageType);

            var lengthOffset = offset;
            offset += 2; // Reserve place for length

            BufferPrimitivies.SetUint32(buffer, ref offset, MAGIC_COOKIE);
            BufferPrimitivies.SetBytes(buffer, ref offset, TransactionId);

            if (MappedAddress != null)
            {
                var startTagOffset = StartTag(buffer, ref offset, Tags.MappedAddress);
                PackAddress(buffer, MappedAddress, ref offset, null);
                StopTag(buffer, ref offset, startTagOffset);
            }

            if (Username != null)
            {
                var startTagOffset = StartTag(buffer, ref offset, Tags.Username);
                BufferPrimitivies.SetBytes(buffer, ref offset, Encoding.UTF8.GetBytes(Username));
                StopTag(buffer, ref offset, startTagOffset);
            }

            if (XorMappedAddress != null)
            {
                var startTagOffset = StartTag(buffer, ref offset, Tags.XorMappedAddress);
                PackAddress(buffer, XorMappedAddress, ref offset, TransactionId);
                StopTag(buffer, ref offset, startTagOffset);
            }

            if (Priority != null)
            {
                var startTagOffset = StartTag(buffer, ref offset, Tags.Priority);
                BufferPrimitivies.SetUint32(buffer, ref offset, Priority.Value);
                StopTag(buffer, ref offset, startTagOffset);
            }

            if (IceControlledTieBreaker != null)
            {
                var startTagOffset = StartTag(buffer, ref offset, Tags.IceControlled);
                BufferPrimitivies.SetUint64(buffer, ref offset, IceControlledTieBreaker.Value);
                StopTag(buffer, ref offset, startTagOffset);
            }

            if (IceControllingTieBreaker != null)
            {
                var startTagOffset = StartTag(buffer, ref offset, Tags.IceControlling);
                BufferPrimitivies.SetUint64(buffer, ref offset, IceControllingTieBreaker.Value);
                StopTag(buffer, ref offset, startTagOffset);
            }

            if (ResponseOrigin != null)
            {
                var startTagOffset = StartTag(buffer, ref offset, Tags.ResponseOrigin);
                PackAddress(buffer, ResponseOrigin, ref offset, null);
                StopTag(buffer, ref offset, startTagOffset);
            }

            if (MessageIntegrityKey != null)
            {
                MessageIntegrityInput = BufferPrimitivies.GetBytes(buffer, startOffset, offset - startOffset);
                BufferPrimitivies.SetUint16(MessageIntegrityInput, 2, (ushort) (offset - startOffset + HMAC_TAG_SIZE - HEADER_SIZE));
                MessageIntegrity = CalcHmac(MessageIntegrityKey);
            }

            if (MessageIntegrity != null)
            {
                var startTagOffset = StartTag(buffer, ref offset, Tags.MessageIntegrity);
                BufferPrimitivies.SetBytes(buffer, ref offset, MessageIntegrity);
                StopTag(buffer, ref offset, startTagOffset);
            }

            if (Fingerprint)
            {
                var startTagOffset = StartTag(buffer, ref offset, Tags.Fingerprint);
                BufferPrimitivies.SetUint32(buffer, ref offset, 0);
                StopTag(buffer, ref offset, startTagOffset);
            }

            BufferPrimitivies.SetUint16(buffer, lengthOffset, (ushort) (offset - startOffset - HEADER_SIZE));

            if (Fingerprint)
            {
                var calcFingerprint = StunCrc32.Calc(buffer, startOffset, offset - startOffset - 8) ^ FINGERPRINT_MASK;
                BufferPrimitivies.SetUint32(buffer, offset - 4, calcFingerprint);
            }
        }

        public bool VerifyIntegrity(byte[] key)
        {
            return ValidateHmac(CalcHmac(key));
        }
    }
}