// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright 2019 Artem Yamshanov, me [at] anticode.ninja

﻿namespace PttOnWebRtc
{
    using System.Collections.Generic;
    using System.Text;

    public class BufferPrimitives
    {
        public static byte GetUint8(byte[] buffer, ref int offset) => (byte) GetVarious(buffer, ref offset, 1);
        public static byte GetUint8(byte[] buffer, int offset) => (byte) GetVarious(buffer, ref offset, 1);

        public static ushort GetUint16(byte[] buffer, ref int offset) => (ushort) GetVarious(buffer, ref offset, 2);
        public static ushort GetUint16(byte[] buffer, int offset) => (ushort) GetVarious(buffer, ref offset, 2);

        public static uint GetUint32(byte[] buffer, ref int offset) => (uint) GetVarious(buffer, ref offset, 4);
        public static uint GetUint32(byte[] buffer, int offset) => (uint) GetVarious(buffer, ref offset, 4);

        public static ulong GetUint64(byte[] buffer, ref int offset) => GetVarious(buffer, ref offset, 8);
        public static ulong GetUint64(byte[] buffer, int offset) => GetVarious(buffer, ref offset, 8);

        public static ulong GetVarious(byte[] buffer, int offset, int count) => GetVarious(buffer, ref offset, count);
        public static ulong GetBits(byte[] buffer, int offset, int bitOffset, int bitCount)
            => GetBits(buffer, offset, ref bitOffset, bitCount);

        public static byte[] GetBytes(byte[] buffer, int offset, int count) => GetBytes(buffer, ref offset, count);

        public static ulong GetVarious(byte[] buffer, ref int offset, int count)
        {
            ulong result = 0;
            for (var i = 0; i < count; ++i) result = (result << 8) | buffer[offset++];
            return result;
        }

        public static ulong GetBits(byte[] buffer, int offset, ref int bitOffset, int bitCount)
        {
            ulong result = 0;

            while (bitCount > 0)
            {
                var inByteOffset = bitOffset & 0x7;
                var inByteCount = 8 - inByteOffset;
                // MAGIC: set inByteCount = bitCount if inByteCount > bitCount
                inByteCount -= ((bitCount - inByteCount) >> 31) & (inByteCount - bitCount);
                var byteOffset = offset + (bitOffset >> 3);
                var mask = (1 << inByteCount) - 1;

                result = result << inByteCount | (ulong)(buffer[byteOffset] >> (8 - inByteOffset - inByteCount) & mask);

                bitOffset += inByteCount;
                bitCount -= inByteCount;
            }

            return result;
        }

        public static byte[] GetBytes(byte[] buffer, ref int offset, int count)
        {
            var temp = new byte[count];
            for (var i = 0; i < count; ++i) temp[i] = buffer[offset++];
            return temp;
        }

        public static void SetUint8(byte[] buffer, ref int offset, byte data) => SetVarious(buffer, ref offset, data, 1);
        public static void SetUint8(byte[] buffer, int offset, byte data) => SetVarious(buffer, ref offset, data, 1);

        public static void SetUint16(byte[] buffer, ref int offset, ushort data) => SetVarious(buffer, ref offset, data, 2);
        public static void SetUint16(byte[] buffer, int offset, ushort data) => SetVarious(buffer, ref offset, data, 2);

        public static void SetUint32(byte[] buffer, ref int offset, uint data) => SetVarious(buffer, ref offset, data, 4);
        public static void SetUint32(byte[] buffer, int offset, uint data) => SetVarious(buffer, ref offset, data, 4);

        public static void SetUint64(byte[] buffer, ref int offset, ulong data) => SetVarious(buffer, ref offset, data, 8);
        public static void SetUint64(byte[] buffer, int offset, ulong data) => SetVarious(buffer, ref offset, data, 8);

        public static void SetVarious(byte[] buffer, int offset, ulong data, int count) => SetVarious(buffer, ref offset, data, count);
        public static void SetBits(byte[] buffer, int offset, int bitOffset, int bitCount, ulong data)
            => SetBits(buffer, offset, ref bitOffset, bitCount, data);

        public static void SetBytes(byte[] buffer, ref int offset, byte[] data) => SetBytes(buffer, ref offset, data, 0, data.Length);
        public static void SetBytes(byte[] buffer, int offset, byte[] data) => SetBytes(buffer, ref offset, data, 0, data.Length);
        public static void SetBytes(byte[] buffer, int offset, byte[] data, int index, int count) => SetBytes(buffer, ref offset, data, index, count);

        public static void SetVarious(byte[] buffer, ref int offset, ulong data, int count)
        {
            for (var i = 0; i < count; ++i) buffer[offset++] = (byte) (data >> (8 * (count - i - 1)));
        }

        public static void SetBits(byte[] buffer, int offset, ref int bitOffset, int bitCount, ulong data)
        {
            while (bitCount > 0)
            {
                var inByteOffset = bitOffset & 0x7;
                var inByteCount = 8 - inByteOffset;
                // MAGIC: set rShift if bitCount > inByteCount
                var rShift = ((inByteCount - bitCount) >> 31) & (bitCount - inByteCount);
                // MAGIC: set lShift if inByteCount > bitCount
                var lShift = ((bitCount - inByteCount) >> 31) & (inByteCount - bitCount);
                // MAGIC: set inByteCount = bitCount if inByteCount > bitCount
                inByteCount -= ((bitCount - inByteCount) >> 31) & (inByteCount - bitCount);
                var byteOffset = offset + (bitOffset >> 3);
                var mask = (byte)~(((1 << inByteCount) - 1) << lShift);

                buffer[byteOffset] = (byte) (buffer[byteOffset] & mask | ((byte)(data >> rShift) << lShift));

                bitOffset += inByteCount;
                bitCount -= inByteCount;
            }
        }

        public static void SetBytes(byte[] buffer, ref int offset, byte[] data, int index, int count)
        {
            for (var i = 0; i < count; ++i) buffer[offset++] = data[index + i];
        }

        public static byte[] ParseHexStream(string input)
        {
            var temp = new List<byte>();

            int index = 0;
            foreach (var i in input)
            {
                byte current;

                if ('0' <= i && i <= '9')
                    current = (byte) (i - '0');
                else if ('a' <= i && i <= 'f')
                    current = (byte) (10 + i - 'a');
                else if ('A' <= i && i <= 'F')
                    current = (byte) (10 + i - 'A');
                else
                    continue;

                if (index >= temp.Count)
                    temp.Add((byte) (current << 4));
                else
                    temp[index++] |= current;
            }

            return temp.ToArray();
        }

        public static string ToHexStream(byte[] input)
        {
            var sb = new StringBuilder(2 * input.Length);
            for (var i = 0; i < input.Length; ++i)
                sb.AppendFormat("{0:X2}", input[i]);
            return sb.ToString();
        }
    }
}