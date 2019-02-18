// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright 2019 Artem Yamshanov, me [at] anticode.ninja

namespace PttOnWebRtc
{
    using System;
    using System.Runtime.InteropServices;

    public class SrtpContext
    {
        public const int SRTP_MASTER_KEY_LEN = 16;
        public const int SRTP_MASTER_SALT_LEN = 14;
        public const int SRTP_MASTER_LEN = SRTP_MASTER_KEY_LEN + SRTP_MASTER_SALT_LEN;
        public const int BLOCK_SIZE = 16;
        public const int AUTH_TAG_SIZE = 10;
        public const int HMAC_SHA1_SIZE = 20;

        private IntPtr _ctx;

        private uint _txRoc;
        private byte[] _txKey;
        private byte[] _txSalt;

        private uint _rxRoc;
        private byte[] _rxKey;
        private byte[] _rxSalt;

        public SrtpContext()
        {
            _ctx = OpenSsl.EVP_CIPHER_CTX_new();
            _txKey = new byte[SRTP_MASTER_KEY_LEN];
            _txSalt = new byte[SRTP_MASTER_SALT_LEN];
            _rxKey = new byte[SRTP_MASTER_KEY_LEN];
            _rxSalt = new byte[SRTP_MASTER_SALT_LEN];
            // TODO implement Dispose
        }

        public byte[] PackSrtpPacket(RtpPacket packet)
        {
            var offset = 0;
            var buffer = new byte[RtpPacket.BUFFER_SIZE];
            packet.Pack(buffer, ref offset);

            var sessionKey = new byte[16];
            var sessionSalt = new byte[16];
            var sessionAuth = new byte[32];

            // TODO add _txRoc logic
            var index = ((ulong)_txRoc << 16) + packet.SequenceNumber;
            GenerateSessionKey(_txKey, _txSalt, sessionKey, sessionSalt, sessionAuth);

            var sessionIv = new byte[BLOCK_SIZE];
            var temp = new byte[BLOCK_SIZE];
            for (var i = 0; i < 14; ++i) sessionIv[i] = sessionSalt[i];
            BufferPrimitivies.SetUint32(temp, 4, packet.Ssrc);
            for (var i = 4; i < 8; ++i) sessionIv[i] ^= temp[i];
            BufferPrimitivies.SetVarious(temp, 8, index, 6);
            for (var i = 8; i < 14; ++i) sessionIv[i] ^= temp[i];

            var keyStream = new byte[packet.Payload.Length];
            var payloadOffset = offset - packet.Payload.Length;
            GenerateKeyStream(sessionKey, sessionIv, keyStream);
            for (var i = 0; i < packet.Payload.Length; ++i) buffer[payloadOffset + i] = (byte)(packet.Payload[i] ^ keyStream[i]);

            var hmac = new byte[HMAC_SHA1_SIZE];
            BufferPrimitivies.SetVarious(buffer, offset, _txRoc, 4);
            CalcHmac(sessionAuth, 20, buffer, offset + 4, hmac);
            BufferPrimitivies.SetBytes(buffer, ref offset, hmac, 0, 10);

            return BufferPrimitivies.GetBytes(buffer, 0, offset);
        }

        public RtpPacket.ResultCodes TryParseSrtpPacket(byte[] data, out RtpPacket packet)
        {
            var result = RtpPacket.TryParse(data, out packet);
            if (result != RtpPacket.ResultCodes.Ok)
                return result;

            var packetSize = data.Length - AUTH_TAG_SIZE;
            var payloadLength = packet.Payload.Length - AUTH_TAG_SIZE;

            var sessionKey = new byte[16];
            var sessionSalt = new byte[16];
            var sessionAuth = new byte[32];

            // TODO add _rxRoc logic
            var index = ((ulong)_rxRoc << 16) + packet.SequenceNumber;
            GenerateSessionKey(_rxKey, _rxSalt, sessionKey, sessionSalt, sessionAuth);

            var hmacData = new byte[packetSize + 4];
            var hmac = new byte[HMAC_SHA1_SIZE];
            Array.Copy(data, 0, hmacData, 0, packetSize);
            BufferPrimitivies.SetVarious(hmacData, packetSize, _rxRoc, 4);
            CalcHmac(sessionAuth, 20, hmacData, packetSize + 4, hmac);

            for (var i = 0; i < AUTH_TAG_SIZE; ++i)
                if (data[packetSize + i] != hmac[i])
                    return RtpPacket.ResultCodes.IncorrectSign;

            var sessionIv = new byte[BLOCK_SIZE];
            var temp = new byte[BLOCK_SIZE];
            for (var i = 0; i < 14; ++i) sessionIv[i] = sessionSalt[i];
            BufferPrimitivies.SetUint32(temp, 4, packet.Ssrc);
            for (var i = 4; i < 8; ++i) sessionIv[i] ^= temp[i];
            BufferPrimitivies.SetVarious(temp, 8, index, 6);
            for (var i = 8; i < 14; ++i) sessionIv[i] ^= temp[i];

            var keyStream = new byte[payloadLength];
            var payload = new byte[payloadLength];
            GenerateKeyStream(sessionKey, sessionIv, keyStream);
            for (var i = 0; i < payloadLength; ++i) payload[i] = (byte)(packet.Payload[i] ^ keyStream[i]);

            packet.Payload = payload;
            return RtpPacket.ResultCodes.Ok;
        }

        public void SetMasterKeys(IntPtr ssl, bool isClient)
        {
            var keyingMaterialHandle = default(GCHandle);

            try
            {
                var keyingMaterial = new byte[2 * SRTP_MASTER_LEN];
                keyingMaterialHandle = GCHandle.Alloc(keyingMaterial, GCHandleType.Pinned);

                if (OpenSsl.SSL_export_keying_material(ssl, keyingMaterialHandle.AddrOfPinnedObject(),
                        2 * SRTP_MASTER_LEN,
                        Marshal.StringToHGlobalAnsi("EXTRACTOR-dtls_srtp"), 19,
                        IntPtr.Zero, 0, 0) != 1)
                    throw new Exception($"Cannot export keying material: {OpenSsl.GetLastError()}");

                int offset = 0;
                Array.Copy(keyingMaterial, offset, isClient ? _txKey : _rxKey, 0, SRTP_MASTER_KEY_LEN);
                offset += SRTP_MASTER_KEY_LEN;
                Array.Copy(keyingMaterial, offset, isClient ? _rxKey : _txKey, 0, SRTP_MASTER_KEY_LEN);
                offset += SRTP_MASTER_KEY_LEN;
                Array.Copy(keyingMaterial, offset, isClient ? _txSalt : _rxSalt, 0, SRTP_MASTER_SALT_LEN);
                offset += SRTP_MASTER_SALT_LEN;
                Array.Copy(keyingMaterial, offset, isClient ? _rxSalt : _txSalt, 0, SRTP_MASTER_SALT_LEN);

                _rxRoc = 0;
                _txRoc = 0;
            }
            finally
            {
                if (keyingMaterialHandle.IsAllocated) keyingMaterialHandle.Free();
            }
        }

        public void SetMasterKeys(byte[] txkey, byte[] txSalt, byte[] rxKey, byte[] rxSalt)
        {
            Array.Copy(txkey, 0, _txKey, 0, SRTP_MASTER_KEY_LEN);
            Array.Copy(txSalt, 0, _txSalt, 0, SRTP_MASTER_SALT_LEN);
            Array.Copy(rxKey, 0, _rxKey, 0, SRTP_MASTER_KEY_LEN);
            Array.Copy(rxSalt, 0, _rxSalt, 0, SRTP_MASTER_SALT_LEN);
            _rxRoc = 0;
            _txRoc = 0;
        }

        public void DumpMasterKeys()
        {
            Console.Out.WriteLineAsync("============== TXKEY TXSALT RXKEY RXSALT ==============");
            Console.Out.WriteLineAsync(BufferPrimitivies.ToHexStream(_txKey));
            Console.Out.WriteLineAsync(BufferPrimitivies.ToHexStream(_txSalt));
            Console.Out.WriteLineAsync(BufferPrimitivies.ToHexStream(_rxKey));
            Console.Out.WriteLineAsync(BufferPrimitivies.ToHexStream(_rxSalt));
            Console.Out.WriteLineAsync("=======================================================");
        }

        public void GenerateKeyStream(byte[] key, byte[] iv, byte[] output)
        {
            if (output.Length % BLOCK_SIZE != 0)
                throw new Exception("Output buffer size must be aligned to BLOCK_SIZE");

            var keyHandle = default(GCHandle);
            var ivHandle = default(GCHandle);
            var inputHandle = default(GCHandle);
            var outputHandle = default(GCHandle);

            try
            {
                var inputBlock = new byte[BLOCK_SIZE];

                keyHandle = GCHandle.Alloc(key, GCHandleType.Pinned);
                ivHandle = GCHandle.Alloc(iv, GCHandleType.Pinned);
                inputHandle = GCHandle.Alloc(inputBlock, GCHandleType.Pinned);
                outputHandle = GCHandle.Alloc(output, GCHandleType.Pinned);

                if (OpenSsl.EVP_EncryptInit_ex(_ctx, OpenSsl.EVP_aes_128_ctr(), IntPtr.Zero,
                        keyHandle.AddrOfPinnedObject(), ivHandle.AddrOfPinnedObject()) != 1)
                    throw new Exception($"Cannot initialize AES: {OpenSsl.GetLastError()}");

                int outputOffset = 0;
                while (outputOffset < output.Length)
                {
                    int outputLength = 0;
                    if (OpenSsl.EVP_EncryptUpdate(_ctx,
                        IntPtr.Add(outputHandle.AddrOfPinnedObject(), outputOffset), ref outputLength,
                        inputHandle.AddrOfPinnedObject(), BLOCK_SIZE) != 1)
                        throw new Exception($"Cannot encode AES: {OpenSsl.GetLastError()}");
                    outputOffset += outputLength;
                }
            }
            finally
            {
                if (keyHandle.IsAllocated) keyHandle.Free();
                if (ivHandle.IsAllocated) ivHandle.Free();
                if (inputHandle.IsAllocated) inputHandle.Free();
                if (outputHandle.IsAllocated) outputHandle.Free();
            }
        }

        public void GenerateSessionKey(
            byte[] masterKey,
            byte[] masterSalt,
            byte[] sessionKey,
            byte[] sessionSalt,
            byte[] sessionAuth
            )
        {
            var keyHandle = default(GCHandle);
            var ivHandle = default(GCHandle);
            var inputHandle = default(GCHandle);
            var sessionKeyHandle = default(GCHandle);
            var sessionSaltHandle = default(GCHandle);
            var sessionAuthHandle = default(GCHandle);

            try
            {
                var inputBlock = new byte[BLOCK_SIZE];
                var sessionIv = new byte[BLOCK_SIZE];

                keyHandle = GCHandle.Alloc(masterKey, GCHandleType.Pinned);
                ivHandle = GCHandle.Alloc(sessionIv, GCHandleType.Pinned);
                inputHandle = GCHandle.Alloc(inputBlock, GCHandleType.Pinned);
                sessionKeyHandle = GCHandle.Alloc(sessionKey, GCHandleType.Pinned);
                sessionSaltHandle = GCHandle.Alloc(sessionSalt, GCHandleType.Pinned);
                sessionAuthHandle = GCHandle.Alloc(sessionAuth, GCHandleType.Pinned);

                Array.Copy(masterSalt, sessionIv, masterSalt.Length);

                if (OpenSsl.EVP_EncryptInit_ex(_ctx, OpenSsl.EVP_aes_128_ctr(), IntPtr.Zero,
                        keyHandle.AddrOfPinnedObject(), ivHandle.AddrOfPinnedObject()) != 1)
                    throw new Exception($"Cannot initialize AES: {OpenSsl.GetLastError()}");

                int outputLength = 0;
                if (OpenSsl.EVP_EncryptUpdate(_ctx,
                    sessionKeyHandle.AddrOfPinnedObject(), ref outputLength,
                    inputHandle.AddrOfPinnedObject(), BLOCK_SIZE) != 1)
                    throw new Exception($"Cannot encode AES: {OpenSsl.GetLastError()}");

                sessionIv[7] ^= 0x02;
                if (OpenSsl.EVP_EncryptInit_ex(_ctx, OpenSsl.EVP_aes_128_ctr(), IntPtr.Zero,
                        keyHandle.AddrOfPinnedObject(), ivHandle.AddrOfPinnedObject()) != 1)
                    throw new Exception($"Cannot initialize AES: {OpenSsl.GetLastError()}");

                outputLength = 0;
                if (OpenSsl.EVP_EncryptUpdate(_ctx,
                    sessionSaltHandle.AddrOfPinnedObject(), ref outputLength,
                    inputHandle.AddrOfPinnedObject(), BLOCK_SIZE) != 1)
                    throw new Exception($"Cannot encode AES: {OpenSsl.GetLastError()}");

                sessionIv[7] ^= 0x03;
                if (OpenSsl.EVP_EncryptInit_ex(_ctx, OpenSsl.EVP_aes_128_ctr(), IntPtr.Zero,
                        keyHandle.AddrOfPinnedObject(), ivHandle.AddrOfPinnedObject()) != 1)
                    throw new Exception($"Cannot initialize AES: {OpenSsl.GetLastError()}");

                int outputOffset = 0;
                while (outputOffset < sessionAuth.Length)
                {
                    outputLength = 0;
                    if (OpenSsl.EVP_EncryptUpdate(_ctx,
                        IntPtr.Add(sessionAuthHandle.AddrOfPinnedObject(), outputOffset), ref outputLength,
                        inputHandle.AddrOfPinnedObject(), BLOCK_SIZE) != 1)
                        throw new Exception($"Cannot encode AES: {OpenSsl.GetLastError()}");
                    outputOffset += outputLength;
                }
            }
            finally
            {
                if (keyHandle.IsAllocated) keyHandle.Free();
                if (ivHandle.IsAllocated) ivHandle.Free();
                if (inputHandle.IsAllocated) inputHandle.Free();
                if (sessionKeyHandle.IsAllocated) sessionKeyHandle.Free();
                if (sessionSaltHandle.IsAllocated) sessionSaltHandle.Free();
                if (sessionAuthHandle.IsAllocated) sessionAuthHandle.Free();
            }
        }

        public void CalcHmac(byte[] key, int keyLen, byte[] data, int dataLen, byte[] hmac)
        {
            var keyHandle = default(GCHandle);
            var dataHandle = default(GCHandle);
            var hmacHandle = default(GCHandle);

            try
            {
                keyHandle = GCHandle.Alloc(key, GCHandleType.Pinned);
                dataHandle = GCHandle.Alloc(data, GCHandleType.Pinned);
                hmacHandle = GCHandle.Alloc(hmac, GCHandleType.Pinned);

                var outputLength = 0;
                if (OpenSsl.HMAC(OpenSsl.EVP_sha1(),
                        keyHandle.AddrOfPinnedObject(), keyLen,
                        dataHandle.AddrOfPinnedObject(), dataLen,
                        hmacHandle.AddrOfPinnedObject(), ref outputLength) == IntPtr.Zero)
                    throw new Exception($"Cannot calculate HMAC: {OpenSsl.GetLastError()}");
            }
            finally
            {
                if (keyHandle.IsAllocated) keyHandle.Free();
                if (dataHandle.IsAllocated) dataHandle.Free();
                if (hmacHandle.IsAllocated) hmacHandle.Free();
            }
        }
    }
}