// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright 2019 Artem Yamshanov, me [at] anticode.ninja

namespace PttOnWebRtc
{
    using System;

    public class RtpPacket
    {
        public const int BUFFER_SIZE = 512;
        private const int HEADER_SIZE = 12;

        // TODO combine with other ResultCodes
        public enum ResultCodes
        {
            Ok,
            PacketIsNotRtp,
            IncorrectSign,
        }

        public bool Padding { get; set; }
        public byte[] Extension { get; set; }
        public byte PayloadType { get; set; }
        public bool Marker { get; set; }
        public ushort SequenceNumber { get; set; }
        public uint Timestamp { get; set; }
        public uint Ssrc { get; set; }
        public byte[] Payload { get; set; }

        public static ResultCodes TryParse(byte[] buffer, out RtpPacket output)
        {
            var offset = 0;
            return TryParse(buffer, ref offset, out output);
        }

        public static ResultCodes TryParse(byte[] buffer, ref int offset, out RtpPacket output)
        {
            output = null;

            if (offset + HEADER_SIZE > buffer.Length)
                return ResultCodes.PacketIsNotRtp;

            var temp = new RtpPacket();

            if ((buffer[offset] & 0xc0) != 0x80)
                return ResultCodes.PacketIsNotRtp;
            temp.Padding = (buffer[offset] & 0x20) != 0;
            var extension = (buffer[offset] & 0x10) != 0;
            var contributingSourceCount = buffer[offset] & 0x0f;
            offset += 1;

            temp.Marker = (buffer[offset] & 0x80) != 0;
            temp.PayloadType = (byte)(buffer[offset] & 0x7f);
            offset += 1;

            temp.SequenceNumber = BufferPrimitivies.GetUint16(buffer, ref offset);
            temp.Timestamp = BufferPrimitivies.GetUint32(buffer, ref offset);
            temp.Ssrc = BufferPrimitivies.GetUint32(buffer, ref offset);

            offset += contributingSourceCount * 4; // TODO implement CSRC
            if (extension)
            {
                var extensionCount = BufferPrimitivies.GetUint32(buffer, ref offset);
                offset += (int)extensionCount * 4; // TODO implement Extension
            }

            temp.Payload = BufferPrimitivies.GetBytes(buffer, ref offset, buffer.Length - offset);

            output = temp;
            return ResultCodes.Ok;
        }

        public byte[] Pack()
        {
            int offset = 0;
            var buffer = new byte[BUFFER_SIZE];
            Pack(buffer, ref offset);
            return BufferPrimitivies.GetBytes(buffer, 0, offset);
        }

        public void Pack(byte[] buffer, ref int offset)
        {
            buffer[offset] = 0x80;
            if (Padding) buffer[offset] |= 0x20;
            if (Extension != null) buffer[offset] |= 0x10;
            // TODO implement CSRC
            offset += 1;

            buffer[offset] = (byte)(Marker ? 0x80 : 0x00);
            buffer[offset] |= PayloadType;
            offset += 1;

            BufferPrimitivies.SetUint16(buffer, ref offset, SequenceNumber);
            BufferPrimitivies.SetUint32(buffer, ref offset, Timestamp);
            BufferPrimitivies.SetUint32(buffer, ref offset, Ssrc);

            // TODO impement CSRC and Extension

            BufferPrimitivies.SetBytes(buffer, ref offset, Payload);
        }
    }
}