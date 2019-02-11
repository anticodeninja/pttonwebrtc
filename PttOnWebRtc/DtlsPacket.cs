// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright 2019 Artem Yamshanov, me [at] anticode.ninja

﻿namespace PttOnWebRtc
{
    using System;

    class DtlsPacket
    {
        private const int HEADER_SIZE = 13;

        public enum ProtocolVersions
        {
            Dtls1_0 = 0xfeff,
            Dtls1_2 = 0xfefd,
        }

        public enum ResultCodes
        {
            Ok,
            IncorrectPacket,
        }

        public static ResultCodes CheckPacket(byte[] data, int offset)
        {
            if (offset + data.Length < HEADER_SIZE) return ResultCodes.IncorrectPacket;
            if (data[offset] < 20 || data[offset] > 63) return ResultCodes.IncorrectPacket;
            if (data[offset + 1] != 0xfe || data[offset + 2] != 0xff && data[offset + 2] != 0xfd)
                return ResultCodes.IncorrectPacket;
            return ResultCodes.Ok;
        }
    }
}