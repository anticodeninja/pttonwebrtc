// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright 2019 Artem Yamshanov, me [at] anticode.ninja

namespace PttOnWebRtc
{
    using System;
    using System.Runtime.InteropServices;

    public static class OpenSsl
    {
        private const string CryptoDllName = "libcrypto.so";

        private const string SslDllName = "libssl.so";

        public enum BioCtrls
        {
            Push = 6,
            Pop = 7,
            Flush = 11,
            WPending = 13,
            DgramQueryMtu = 40,
            DgramSetMtu = 42,
            DgramSetNextTimeout = 45,
            DgramGetMtuOverhead = 49,
        }

        private const int SRTP_MASTER_KEY_LEN = 16;
        private const int SRTP_MASTER_SALT_LEN = 14;
        private const int SRTP_MASTER_LEN = SRTP_MASTER_KEY_LEN + SRTP_MASTER_SALT_LEN;

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int ErrCb(IntPtr str, uint len, IntPtr u);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int WriteCb(IntPtr bio, IntPtr data, int dlen);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int ReadCb(IntPtr bio, IntPtr data, int dlen);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate long CtrlCb(IntPtr bio, int cmd, long larg, IntPtr parg);

        [DllImport(CryptoDllName, CallingConvention = CallingConvention.Cdecl)]
        public extern static void ERR_print_errors_cb(ErrCb cb, IntPtr u);

        // BIO

        [DllImport(CryptoDllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr BIO_s_mem();

        [DllImport(CryptoDllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr BIO_meth_new(int type, string name);

        [DllImport(CryptoDllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int BIO_meth_set_write(IntPtr b, WriteCb cb);

        [DllImport(CryptoDllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int BIO_meth_set_read(IntPtr b, ReadCb cb);

        [DllImport(CryptoDllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int BIO_meth_set_ctrl(IntPtr b, CtrlCb cb);

        [DllImport(CryptoDllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr BIO_new(IntPtr bp);

        [DllImport(CryptoDllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int BIO_write(IntPtr b, byte[] buf, int len);

        [DllImport(CryptoDllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void BIO_set_data(IntPtr b, IntPtr ptr);

        [DllImport(CryptoDllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr BIO_get_data(IntPtr b);

        [DllImport(CryptoDllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void BIO_free_all(IntPtr bio);

        // Crypto

        [DllImport(CryptoDllName, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr PEM_read_bio_X509(IntPtr bp, IntPtr x, IntPtr cb, IntPtr u);

        [DllImport(CryptoDllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr PEM_read_bio_PrivateKey(IntPtr bp, IntPtr x, IntPtr cb, IntPtr u);

        [DllImport(CryptoDllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void EVP_PKEY_free(IntPtr pkey);

        [DllImport(CryptoDllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr EVP_CIPHER_CTX_new();

        [DllImport(CryptoDllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr EVP_aes_128_ctr();

        [DllImport(CryptoDllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr EVP_sha1();

        [DllImport(CryptoDllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int EVP_EncryptInit_ex(IntPtr ctx, IntPtr cipher, IntPtr engine, IntPtr key, IntPtr iv);

        [DllImport(CryptoDllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int EVP_EncryptUpdate(IntPtr ctx,
                                                   IntPtr output, ref int outputLen,
                                                   IntPtr input, int inputLen);

        [DllImport(CryptoDllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr HMAC(IntPtr evp_md, IntPtr key, int keyLen,
                    IntPtr data, int dataLen, IntPtr md, ref int digestLen);

        // SSL

        [DllImport(SslDllName, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr DTLS_method();

        [DllImport(SslDllName, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr SSL_CTX_new(IntPtr sslMethod);

        [DllImport(SslDllName, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_CTX_use_certificate(IntPtr ctx, IntPtr cert);

        [DllImport(SslDllName, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_CTX_use_PrivateKey(IntPtr ctx, IntPtr pkey);

        [DllImport(SslDllName, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_CTX_set_tlsext_use_srtp(IntPtr ctx, string profiles);

        [DllImport(SslDllName, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr SSL_new(IntPtr ctx);

        [DllImport(SslDllName, CallingConvention = CallingConvention.Cdecl)]
        public extern static void SSL_set_bio(IntPtr ssl, IntPtr read_bio, IntPtr write_bio);

        [DllImport(SslDllName, CallingConvention = CallingConvention.Cdecl)]
        public extern static void SSL_set_connect_state(IntPtr ssl);

        [DllImport(SslDllName, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_do_handshake(IntPtr ssl);

        [DllImport(SslDllName, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_write(IntPtr ssl, IntPtr buf, int num);

        [DllImport(SslDllName, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_export_keying_material(IntPtr ssl,
            IntPtr buffer, int olen, IntPtr label, int llen,
            IntPtr context, int contextlen, int use_context);

        private static string _lastError;

        public static string GetLastError()
        {
            ERR_print_errors_cb(WriteError, IntPtr.Zero);
            return _lastError;
        }

        private static int WriteError(IntPtr str, uint len, IntPtr u)
        {
            _lastError = Marshal.PtrToStringAuto(str, (int) len);
            return 0;
        }
    }
}